"""``sensitive = true`` coverage audit over ``.tf`` files.

Two findings:

* **unmarked** -- a ``variable`` or ``output`` whose name looks like a secret but
  which is not declared ``sensitive = true``. These print in cleartext in
  ``terraform plan`` and ``terraform output -json``.
* **hardcoded** -- a resource attribute whose name looks like a secret and whose
  value is a literal string instead of a reference to a variable. The value lands
  in state, config review, and every future ``terraform show``.

Parsing is brace-balanced text scanning rather than a full HCL parse. Terraform
config grammar is large, but the constructs audited here are regular enough that
no dependency is worth it -- and a dependency would be the thing users complain
about.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .detectors import _key_hint, is_placeholder

__all__ = [
    "Block",
    "BlockFinding",
    "audit_file",
    "audit_dir",
    "AuditResult",
]

BLOCK_HDR_RE = re.compile(
    r'^\s*(?P<block>variable|output|locals|resource)\s+'
    r'(?:"(?P<first>[^"]+)"|(?P<bare>[A-Za-z_][\w\-]*))'
    r'(?:\s*"(?P<second>[^"]+)")*\s*(?P<rest>{.*)$'
)
SENSITIVE_RE = re.compile(r"^\s*sensitive\s*=\s*true\b", re.IGNORECASE)
TYPE_RE = re.compile(r"^\s*type\s*=\s*(.+?)\s*$")
ATTR_RE = re.compile(
    r'^\s*(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(?P<value>.+?)\s*$'
)
LITERAL_RE = re.compile(r"^[\"']")
_VAR_REF_RE = re.compile(r"^var\.[A-Za-z_][\w\-]*$")
_STRING_RE = re.compile(r"^\"(.*)\"$", re.DOTALL)

SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".terraform",
    "vendor", "dist", "build", ".idea", ".vscode", "coverage", ".mypy_cache",
    ".pytest_cache", "target", ".turbo",
})

TF_EXTENSIONS = {".tf", ".tfvars", ".tftest.hcl"}


@dataclass(frozen=True)
class Block:
    """A top-level HCL block: ``variable "foo" { ... }``."""

    kind: str
    name: str
    body: str
    header_line: int
    start_line: int
    end_line: int
    file: str

    @property
    def is_sensitive(self) -> bool:
        for line in self.body.splitlines():
            if SENSITIVE_RE.match(line):
                return True
        return False

    @property
    def type_decl(self) -> str:
        for line in self.body.splitlines():
            m = TYPE_RE.match(line)
            if m:
                return m.group(1).strip()
        return ""

    @property
    def header_line_no(self) -> int:
        return self.header_line


@dataclass
class BlockFinding:
    """One audit finding."""

    kind: str                      # "variable" | "output"
    name: str
    secret_type: str
    file: str
    line: int
    detail: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "secret_type": self.secret_type,
            "file": self.file,
            "line": self.line,
            "detail": self.detail,
            **self.extra,
        }


@dataclass
class AuditResult:
    files_scanned: int = 0
    blocks_scanned: int = 0
    unmarked: List[BlockFinding] = field(default_factory=list)
    hardcoded: List[BlockFinding] = field(default_factory=list)

    @property
    def findings(self) -> List[BlockFinding]:
        return self.unmarked + self.hardcoded

    def summary(self) -> Dict[str, object]:
        return {
            "files_scanned": self.files_scanned,
            "blocks_scanned": self.blocks_scanned,
            "unmarked_sensitive": len(self.unmarked),
            "hardcoded_secrets": len(self.hardcoded),
            "total": len(self.findings),
        }


def _read_lines(path: str) -> Tuple[List[str], str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines(True), path
    except OSError as exc:
        raise AuditError(f"cannot read {path}: {exc}") from exc


def _extract_blocks(lines: Sequence[str], rel: str) -> List[Block]:
    blocks: List[Block] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.lstrip().startswith("#") or not line.strip():
            i += 1
            continue
        m = BLOCK_HDR_RE.match(line)
        if not m:
            i += 1
            continue
        name = m.group("first") or m.group("bare") or ""
        if m.group("second"):
            # ``resource "aws_instance" "app" {`` -> address ``aws_instance.app``
            name = f"{name}.{m.group('second')}"
        kind = m.group("block")
        rest = m.group("rest")
        # Depth starts at the header's brace.
        depth = rest.count("{") - rest.count("}")
        start = i + 1
        header_line = i + 1
        body_lines: List[str] = []
        if depth == 0 and rest.endswith("}"):
            body_lines.append(rest[:-1].lstrip("{").strip())
            if body_lines and body_lines[0] == "":
                body_lines.pop()
            blocks.append(Block(kind, name, "\n".join(body_lines), header_line,
                                start, i + 1, rel))
            i += 1
            continue
        i += 1
        while i < n and depth > 0:
            current = lines[i]
            depth += current.count("{") - current.count("}")
            body_lines.append(current.rstrip("\n"))
            i += 1
            if depth <= 0:
                break
        blocks.append(Block(kind, name, "\n".join(body_lines), header_line,
                            start, i, rel))
    return blocks


def _line_of(body: str, target: str) -> int:
    idx = body.find(target)
    return 1 + (body[:idx].count("\n") if idx >= 0 else 0)


def audit_file(path: str, rel: Optional[str] = None) -> AuditResult:
    """Audit a single ``.tf`` file."""
    lines, _ = _read_lines(path)
    rel = rel or path
    result = AuditResult()
    blocks = _extract_blocks(lines, rel)
    result.files_scanned = 1
    result.blocks_scanned = len(blocks)

    for block in blocks:
        if block.kind == "resource":
            result.hardcoded.extend(_audit_resource_hardcoded(block))
            continue
        if block.kind not in {"variable", "output"}:
            continue
        secret_type = _key_hint(block.name)
        if secret_type is None:
            continue
        if block.is_sensitive:
            continue
        result.unmarked.append(BlockFinding(
            kind=block.kind,
            name=block.name,
            secret_type=secret_type,
            file=rel,
            line=block.header_line,
            detail=("variable" if block.kind == "variable" else "output")
                   + " holds a secret-looking value but is not declared "
                     "sensitive = true; terraform will print it in cleartext.",
            extra={"type": block.type_decl},
        ))
    return result


def _audit_resource_hardcoded(block: Block) -> List[BlockFinding]:
    """Flag literal secrets inside a resource block body."""
    findings: List[BlockFinding] = []
    for raw_line in block.body.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = ATTR_RE.match(raw_line)
        if not m:
            continue
        key, value = m.group("key"), m.group("value").rstrip(",").strip()
        if value.startswith("[") or value.startswith("{") or value.startswith("<<"):
            continue
        if not LITERAL_RE.match(value):
            continue
        unquoted = _STRING_RE.match(value)
        literal = unquoted.group(1) if unquoted else value[1:-1]
        if is_placeholder(literal):
            continue
        secret_type = _key_hint(key)
        if secret_type is None:
            continue
        findings.append(BlockFinding(
            kind="resource",
            name=f"{block.name}.{key}",
            secret_type=secret_type,
            file=block.file,
            line=block.header_line + _line_of(block.body, raw_line),
            detail=f"{key} is set to a literal value in resource "
                   f"{block.name}; it will be written to state. Reference a "
                   "sensitive variable instead.",
            extra={"attribute": key},
        ))
    return findings


def iter_tf_files(root: str) -> Iterable[str]:
    import os

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in filenames:
            if os.path.splitext(filename)[1] in TF_EXTENSIONS:
                yield os.path.join(dirpath, filename)


def audit_dir(root: str) -> AuditResult:
    """Audit every ``.tf`` file under ``root``."""
    import os

    result = AuditResult()
    for path in sorted(iter_tf_files(root)):
        rel = os.path.relpath(path, root)
        part = audit_file(path, rel)
        result.files_scanned += part.files_scanned
        result.blocks_scanned += part.blocks_scanned
        result.unmarked.extend(part.unmarked)
        result.hardcoded.extend(part.hardcoded)
    result.unmarked.sort(key=lambda f: (f.file, f.line))
    result.hardcoded.sort(key=lambda f: (f.file, f.line))
    return result


class AuditError(Exception):
    """Raised for unreadable HCL input."""
