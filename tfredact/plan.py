"""Terraform plan scanning -- console output and ``terraform show -json``.

Why this exists: ``terraform plan`` is routinely pasted into PR comments, CI
logs and support tickets. ``sensitive = true`` redacts only values that are
*derived from* a sensitive input, so provider attributes such as ``kube_config``
or a password echoed inside a ``user_data`` heredoc print in cleartext. This
module finds those in free-form console text, with no terraform binary required.

Two entry points:

* :func:`scan_plan_text` -- ``terraform plan`` console output, one line at a time.
* :func:`scan_tfplan_json` -- the machine-readable plan from
  ``terraform show -json plan``.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence

from .detectors import (
    HIGH,
    Finding,
    VALUE_DETECTORS,
    _visit_leaf,
    classify_value,
)

__all__ = [
    "PlanFinding",
    "scan_plan_text",
    "scan_tfplan_json",
    "redact_plan_text",
]

# Sentinel values terraform prints instead of a real value. Never findings.
_SKIP_TOKENS = frozenset({
    "(sensitive value)",
    "(sensitive value)",
    "(known after apply)",
    "(known after apply)",
    "(unknown)",
    "sensitive value",
    "known after apply",
    "null",
})

# ``~ password = "old" -> "new"`` / ``+ id = "value"`` / ``  password = ...``
_ATTR_RE = re.compile(
    r"^\s*[~+ -]*\s*"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*"
    r"(?P<value>.*)$"
)

# ``export FOO=bar``, ``FOO: bar``, ``deploy token: AKIA...`` -- assignment and
# colon forms used by cloud-init scripts, docker CMD and plan heredocs.
_ASSIGN_RE = re.compile(
    r"(?i)\b(?P<key>[A-Za-z_][A-Za-z0-9_]{1,60})\s*[=:]\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|\S{4,})"
)

_RESOURCE_HDR_RE = re.compile(
    r'(?:#|\s*[+~ -])\s*(?:(?:module\.\w+\.)+)?(?P<type>[a-z0-9_][\w\-]*)\s*\.\s*'
    r'(?P<name>[^\s{"\']+)'
)
_OUTPUT_HDR_RE = re.compile(r"Changes to Outputs:")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _is_skip(value: str) -> bool:
    v = value.strip()
    if v in _SKIP_TOKENS:
        return True
    if v.startswith("(") and v.endswith(")") and len(v) < 40:
        return True
    return False


def _resource_from_lines(lines: Sequence[str], idx: int) -> str:
    """Walk backwards from ``idx`` to the nearest resource header."""
    for j in range(idx, max(idx - 12, -1), -1):
        if j < 0:
            break
        m = _RESOURCE_HDR_RE.search(lines[j])
        if m:
            name = m.group("name").strip('"[]')
            return f"{m.group('type')}.{name}"
    return ""


class PlanFinding(Finding):
    """A finding located in plan console output."""


def _scan_line_raw(line: str, covered: Sequence[tuple], line_no: int,
                   location: str, out: List[Finding]) -> None:
    """Regex-scan a line, skipping spans already reported by a parsed value."""

    for detector in VALUE_DETECTORS:
        for m in detector._re.finditer(line):
            span = (m.start(), m.end())
            if any(s <= span[0] and span[1] <= e for s, e in covered):
                continue
            if span[1] - span[0] < 6:
                continue
            out.append(Finding(
                path=f"plan:{line_no}",
                secret_type=detector.secret_type,
                value=m.group(0),
                confidence=detector.confidence,
                location=f"{location}:{line_no}" if location else str(line_no),
                detector=detector.secret_type,
                extra={"line_number": line_no, "column": m.start() + 1},
            ))


def scan_plan_text(text: str, location: str = "") -> List[Finding]:
    """Scan ``terraform plan`` console output for secrets.

    Returns findings sorted by line number. ``location`` is prefixed to every
    finding for provenance when scanning a file.
    """
    lines = text.splitlines()
    findings: List[Finding] = []
    current_output = False

    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        if _OUTPUT_HDR_RE.search(line):
            current_output = True
            continue
        if _RESOURCE_HDR_RE.search(line) and "=" not in line:
            current_output = False
            continue

        covered: List[tuple] = []
        parsed_any = False
        m = _ATTR_RE.match(line)
        key = ""
        if m:
            key = m.group("key")
            rhs = m.group("value")
            current_output = False

            # ``"old" -> "new"``: report the changed-to value first, it is the one
            # that will actually be written to state.
            halves = [h.strip() for h in rhs.split("->")]
            candidates: List[str] = []
            if len(halves) == 2:
                candidates = [halves[1], halves[0]]
            else:
                # ``= ["a", "b"]`` or ``= { k = "v" }`` blocks.
                candidates = re.findall(r'"([^"]{4,})"', rhs)
                if not candidates:
                    candidates = [rhs]

            for chunk in candidates:
                value = _unquote(chunk)
                if _is_skip(value):
                    continue
                span = None
                sm = re.search(re.escape(value), line)
                if sm:
                    span = (sm.start(), sm.end())
                    covered.append(span)
                parsed_any = True
                if len(value) < 4:
                    continue
                finding = classify_value(value, key)
                if finding is None:
                    continue
                finding.path = f"plan:{idx}"
                finding.location = f"{location}:{idx}" if location else str(idx)
                finding.extra = {"line_number": idx, "column": (span[0] + 1 if span else None),
                                 "attribute": key}
                findings.append(finding)

        # Fallback: raw regex sweep for heredocs, ``echo`` lines, JSON blobs.
        _scan_line_raw(line, covered, idx, location, findings)

    findings.sort(key=lambda f: f.extra.get("line_number", 0))
    return findings


def scan_tfplan_json(path_or_obj: Any) -> List[Finding]:
    """Scan ``terraform show -json plan`` output.

    Walks ``resource_changes[].change.after`` and ``planned_values``. Entries
    listed in ``after_unknown`` / ``after_sensitive`` are skipped -- they are
    not real values yet.
    """
    if isinstance(path_or_obj, str):
        try:
            with open(path_or_obj, "r", encoding="utf-8") as fh:
                plan = json.load(fh)
        except FileNotFoundError as exc:
            raise PlanError(f"file not found: {path_or_obj}") from exc
        except json.JSONDecodeError as exc:
            raise PlanError(f"{path_or_obj} is not valid JSON: {exc.msg}") from exc
    else:
        plan = path_or_obj

    findings: List[Finding] = []
    changes = plan.get("resource_changes") if isinstance(plan, dict) else None
    if isinstance(changes, list):
        for change in changes:
            if not isinstance(change, dict):
                continue
            address = change.get("address", "")
            kind = change.get("change", {})
            before_unknown = set(change.get("before_unknown", [])) or set()
            after_unknown = set(change.get("after_unknown", [])) or set()
            after_sensitive = set(change.get("after_sensitive", [])) or set()
            for container, key in (("after", "after"), ("before", "before")):
                value = kind.get(container)
                if not isinstance(value, dict):
                    continue
                for attr, raw in value.items():
                    path = f"change.{key}.{attr}"
                    if attr in (before_unknown if key == "before" else after_unknown):
                        continue
                    if isinstance(raw, list) and any(x is None for x in raw):
                        continue
                    nested: List[Finding] = []
                    _visit_leaf(path, str(attr), raw, address, nested)
                    for item in nested:
                        item.extra["address"] = address
                        item.extra["sensitive_marked"] = attr in after_sensitive
                    findings.extend(nested)
    return findings


class PlanError(Exception):
    """Raised for unreadable plan input."""


def redact_plan_text(text: str, token: str = "***REDACTED***") -> str:
    """Return console plan output with every detected secret replaced.

    Used by ``tfredact plan`` to turn ``terraform plan`` into something you can
    paste into a PR comment or support ticket. Line numbers, resource headers,
    ``+``/``~`` symbols and all non-secret values survive.
    """
    lines = text.splitlines(keepends=True)
    out: List[str] = []
    for raw in lines:
        ending = "\n" if raw.endswith("\n") else ""
        line = raw.rstrip("\n")
        replacements: List[tuple] = []

        for detector in VALUE_DETECTORS:
            for m in detector._re.finditer(line):
                if m.end() - m.start() < 6:
                    continue
                replacements.append((m.start(), m.end(), token))

        m = _ATTR_RE.match(line)
        if m:
            key = m.group("key")
            rhs = m.group("value")
            halves = [h.strip() for h in rhs.split("->")]
            if re.match(r"^\s*[\[{]", rhs):
                # ``= ["a", "b"]`` or ``= { k = "v" }``: redact each member.
                candidates = re.findall(r'"([^"]{4,})"', rhs)
            else:
                # ``= "new"`` or ``= "old" -> "new"`` -- both sides are secrets,
                # the state ends up holding them either way.
                candidates = halves
            for chunk in candidates:
                value = _unquote(chunk)
                if _is_skip(value) or len(value) < 4:
                    continue
                if classify_value(value, key) is None:
                    continue
                for span in re.finditer(re.escape(value), line):
                    replacements.append((span.start(), span.end(), token))

        if not replacements:
            out.append(raw)
            continue
        # Merge overlapping ranges, then splice right-to-left so the earlier
        # offsets stay valid.
        merged = []
        for start, end in sorted({(s, e) for s, e, _ in replacements}):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        rebuilt = line
        for start, end in reversed(merged):
            rebuilt = rebuilt[:start] + token + rebuilt[end:]
        out.append(rebuilt + ending)
    return "".join(out)
