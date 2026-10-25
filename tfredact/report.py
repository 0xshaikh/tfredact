"""Human-readable and machine-readable report rendering."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

__all__ = [
    "colors_enabled",
    "Color",
    "findings_as_dict",
    "render_text",
    "render_json",
    "render_audit_text",
    "render_audit_json",
]

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_BAR = "─" * 72


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

    @classmethod
    def paint(cls, text: str, code: str, enabled: bool) -> str:
        return f"{code}{text}{cls.RESET}" if enabled else text


def colors_enabled(stream=any) -> bool:
    if os.environ.get("NOCOLOR"):
        return False
    if os.environ.get("TFREDACT_NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _pad(text: str, width: int) -> str:
    text = str(text)
    if len(text) <= width:
        return text.ljust(width)
    return (text[: width - 1] + "…") if width > 1 else text


def findings_as_dict(findings: Sequence[Any]) -> List[Dict[str, Any]]:
    out = []
    for f in findings:
        out.append({
            "path": f.path,
            "type": f.secret_type,
            "confidence": f.confidence,
            "location": f.location,
            "detector": f.detector,
            "entropy": round(f.entropy, 3) if isinstance(f.entropy, float) else None,
            "nested": bool(f.nested),
            "value_preview": f.preview,
            "extra": dict(f.extra or {}),
        })
    return out


def _confidence_marker(confidence: str, enabled: bool) -> str:
    markers = {
        "high": Color.paint("●", Color.RED, enabled),
        "medium": Color.paint("●", Color.YELLOW, enabled),
        "low": Color.paint("●", Color.DIM, enabled),
    }
    return markers.get(confidence, "●")


def render_text(source: str, summary: Dict[str, Any], findings: Sequence[Any],
                out=None, no_color: bool = False) -> str:
    """Render a scan/redaction report. ``source`` is the file or stream label."""
    out = out or sys.stdout
    enabled = (not no_color) and colors_enabled(out)
    lines: List[str] = []

    title = Color.paint(" tfredact ", Color.CYAN, enabled)
    lines.append(f"{title} {source}")
    lines.append(_BAR)

    total = len(findings)
    if total == 0:
        ok = Color.paint("✓", Color.GREEN, enabled)
        lines.append(f" {ok} No secrets detected.")
        if summary.get("resources_scanned"):
            lines.append(Color.paint(
                f"   scanned {summary['resources_scanned']} resources / "
                f"{summary.get('instances_scanned', 0)} instances",
                Color.DIM, enabled))
        lines.append(_BAR)
        print("\n".join(lines), file=out)
        return "\n".join(lines)

    by_type: Dict[str, int] = {}
    for f in findings:
        by_type[f.secret_type] = by_type.get(f.secret_type, 0) + 1

    lines.append(f" ✗ {Color.paint(str(total), Color.BOLD + Color.RED, enabled)} "
                 f"secret(s) found across {len(by_type)} type(s)")
    lines.append(_BAR)

    for f in findings:
        bullet = _confidence_marker(f.confidence, enabled)
        type_name = Color.paint(f.secret_type, Color.MAGENTA, enabled)
        loc = f.location or f.path
        marked = f.extra.get("sensitive_marked")
        mark_note = ""
        if marked is True:
            mark_note = Color.paint("  [marked sensitive — still stored in state]",
                                    Color.DIM, enabled)
        elif marked is False:
            mark_note = Color.paint("  [NOT marked sensitive]",
                                    Color.YELLOW, enabled)
        lines.append(f" {bullet} {_pad(f.secret_type, 26)} {loc}")
        lines.append(f"     value: {f.preview}")
        lines.append(f"     detector: {Color.paint(f.detector or '-', Color.DIM, enabled)}"
                     f"{mark_note}")

    lines.append(_BAR)

    marked_n = sum(1 for f in findings if f.extra.get("sensitive_marked") is True)
    unmarked_n = sum(1 for f in findings if f.extra.get("sensitive_marked") is False)
    if marked_n or unmarked_n:
        bits = []
        if marked_n:
            bits.append(Color.paint(f"{marked_n} marked sensitive", Color.DIM, enabled))
        if unmarked_n:
            bits.append(Color.paint(
                f"{unmarked_n} NOT marked sensitive", Color.YELLOW, enabled))
        lines.append(" " + " · ".join(bits))
    lines.append(f" by type: " + ", ".join(
        f"{k}×{v}" for k, v in sorted(by_type.items(), key=lambda kv: -kv[1])))
    lines.append(_BAR)

    text = "\n".join(lines)
    print(text, file=out)
    return text


def render_json(payload: Dict[str, Any], out=None) -> str:
    out = out or sys.stdout
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    print(text, file=out)
    return text


def render_audit_text(summary: Dict[str, Any], findings: Sequence[Any],
                      out=None, no_color: bool = False) -> str:
    out = out or sys.stdout
    enabled = (not no_color) and colors_enabled(out)
    lines: List[str] = []
    title = Color.paint(" tfredact audit ", Color.CYAN, enabled)
    lines.append(f"{title} {summary.get('files_scanned', 0)} .tf file(s) scanned, "
                 f"{summary.get('blocks_scanned', 0)} block(s)")
    lines.append(_BAR)

    if not findings:
        ok = Color.paint("✓", Color.GREEN, enabled)
        lines.append(f" {ok} Every secret-bearing variable and output is marked "
                     f"sensitive = true.")
        lines.append(_BAR)
        text = "\n".join(lines)
        print(text, file=out)
        return text

    for f in findings:
        kind = Color.paint(f.kind, Color.BLUE, enabled)
        head = Color.paint(f"{f.name}", Color.BOLD, enabled)
        loc = f"{f.file}:{f.line}"
        lines.append(f" ✗ {loc}  {kind} {head}")
        lines.append(f"     {f.detail}")
        if f.extra.get("type"):
            lines.append(f"     type: {f.extra['type']}")

    lines.append(_BAR)
    lines.append(f" {len(findings)} issue(s): "
                 f"{len([f for f in findings if f.kind == 'resource'])} hardcoded, "
                 f"{len([f for f in findings if f.kind != 'resource'])} unmarked")
    lines.append(_BAR)
    text = "\n".join(lines)
    print(text, file=out)
    return text


def render_audit_json(summary: Dict[str, Any], findings: Sequence[Any],
                      out=None) -> str:
    out = out or sys.stdout
    payload = {
        "summary": summary,
        "unmarked_sensitive": [f.as_dict() for f in findings if f.kind != "resource"],
        "hardcoded_secrets": [f.as_dict() for f in findings if f.kind == "resource"],
    }
    return render_json(payload, out)
