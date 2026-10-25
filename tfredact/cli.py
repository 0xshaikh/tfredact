"""Command-line interface for tfredact."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .detectors import Finding
from .hcl import AuditError, AuditResult, audit_dir, audit_file
from .plan import PlanError, redact_plan_text, scan_plan_text, scan_tfplan_json
from .redact import (
    RedactError,
    redact_state,
    redact_tfplan_json,
)
from .report import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    findings_as_dict,
    render_audit_json,
    render_audit_text,
    render_json,
    render_text,
)
from .state import StateError, scan_state

_STATE_HINTS = (".tfstate", "tfstate", ".terraform.tfstate")
_PLAN_JSON_KEYS = {"format_version", "resource_changes", "planned_values"}

MIN_CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}


def _confidence_ok(finding: Finding, minimum: str) -> bool:
    return MIN_CONFIDENCE_ORDER.get(finding.confidence, 0) >= MIN_CONFIDENCE_ORDER.get(
        minimum, 0)


def _looks_like_state_file(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(_STATE_HINTS)


def _load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _is_state_document(obj: Optional[Dict[str, Any]]) -> bool:
    if not obj:
        return False
    return "resources" in obj and ("version" in obj or "terraform_version" in obj)


def _is_plan_document(obj: Optional[Dict[str, Any]]) -> bool:
    if not obj:
        return False
    return bool(_PLAN_JSON_KEYS & set(obj.keys()))


def _scan_one(path: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Scan one path, dispatching on its shape."""
    obj = _load_json(path) if os.path.isfile(path) else None

    if _is_state_file_kind(path, obj):
        result = scan_state(path)
        findings = [f for f in result.secret_findings if _confidence_ok(f, args.min_confidence)]
        return {
            "source": path,
            "kind": "state",
            "summary": result.summary(),
            "findings": findings,
        }
    if obj is not None and _is_plan_document(obj):
        findings = [f for f in scan_tfplan_json(obj)
                    if _confidence_ok(f, args.min_confidence)]
        return {
            "source": path,
            "kind": "tfplan-json",
            "summary": {
                "path": path,
                "findings": len(findings),
                "by_type": _counts(findings),
            },
            "findings": findings,
        }

    # Free-form console output.
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise CLIError(f"cannot read {path}: {exc}") from exc
    findings = [f for f in scan_plan_text(text, location=path)
                if _confidence_ok(f, args.min_confidence)]
    return {
        "source": path,
        "kind": "plan-text",
        "summary": {
            "path": path,
            "lines": len(text.splitlines()),
            "findings": len(findings),
            "by_type": _counts(findings),
        },
        "findings": findings,
    }


def _is_state_file_kind(path: str, obj: Optional[Dict[str, Any]]) -> bool:
    if _looks_like_state_file(path):
        return True
    return _is_state_document(obj)


def _counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.secret_type] = counts.get(f.secret_type, 0) + 1
    return dict(sorted(counts.items()))


def _expand_paths(paths: Sequence[str]) -> List[str]:
    """Expand directories into the files they contain."""
    expanded: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames[:] = [d for d in dirnames if not d.startswith(".")
                               and d not in {"node_modules", ".venv", "venv",
                                             "__pycache__", ".terraform"}]
                for filename in sorted(filenames):
                    if (filename.endswith(_STATE_HINTS) or filename.endswith(".txt")
                            or filename.endswith(".log") or filename.endswith(".json")
                            or filename.endswith(".json.gz")):
                        expanded.append(os.path.join(dirpath, filename))
        else:
            expanded.append(path)
    seen = set()
    ordered = []
    for p in expanded:
        if p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def cmd_scan(args: argparse.Namespace) -> int:
    paths = _expand_paths(args.paths)
    if not paths:
        print("tfredact: no files to scan", file=sys.stderr)
        return EXIT_ERROR
    missing = [p for p in paths if not os.path.exists(p)]
    if missing and not args.include_missing:
        print(f"tfredact: not found: {', '.join(missing)}", file=sys.stderr)
        return EXIT_ERROR

    reports: List[Dict[str, Any]] = []
    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            reports.append(_scan_one(path, args))
        except (StateError, PlanError) as exc:
            if args.json:
                reports.append({"source": path, "kind": "error",
                                "summary": {"path": path, "error": str(exc)},
                                "findings": []})
            else:
                print(f"tfredact: {path}: {exc}", file=sys.stderr)

    total = sum(len(r["findings"]) for r in reports)

    if args.json:
        payload = {
            "tool": "tfredact",
            "version": __version__,
            "total_findings": total,
            "reports": [
                {
                    **{k: v for k, v in report.items() if k != "findings"},
                    "findings": findings_as_dict(report["findings"]),
                }
                for report in reports
            ],
        }
        render_json(payload, out=sys.stdout)
    else:
        for report in reports:
            render_text(report["source"], report["summary"], report["findings"],
                        out=sys.stdout, no_color=args.no_color)
            print()

    if total == 0:
        return EXIT_CLEAN
    return EXIT_FINDINGS if args.strict else (EXIT_FINDINGS if args.fail_on_findings
                                              else EXIT_CLEAN)


def cmd_redact(args: argparse.Namespace) -> int:
    try:
        with open(args.path, "r", encoding="utf-8") as fh:
            document = json.load(fh)
    except FileNotFoundError as exc:
        print(f"tfredact: file not found: {args.path}", file=sys.stderr)
        return EXIT_ERROR
    except json.JSONDecodeError as exc:
        print(f"tfredact: {args.path} is not valid JSON: {exc.msg}", file=sys.stderr)
        return EXIT_ERROR

    obj = document
    if _is_plan_document(obj):
        redacted, result = redact_tfplan_json(obj)
        kind = "tfplan-json"
    else:
        redacted, result = redact_state(obj)
        kind = "state"

    text = json.dumps(redacted, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        dest = args.output
    elif args.in_place:
        with open(args.path, "w", encoding="utf-8") as fh:
            fh.write(text)
        dest = args.path
    else:
        sys.stdout.write(text)
        dest = "<stdout>"

    payload = {
        "tool": "tfredact",
        "version": __version__,
        "kind": kind,
        "source": args.path,
        "output": dest,
        "values_redacted": result.count,
    }
    if args.json:
        render_json(payload, out=sys.stderr)
        if not args.output and not args.in_place:
            print("tfredact: --json writes the report to stderr; "
                  "redacted JSON is on stdout", file=sys.stderr)
    elif not args.output and args.in_place:
        print(f"tfredact: redacted {result.count} value(s) in {args.path}",
              file=sys.stderr)
    elif args.output:
        print(f"tfredact: redacted {result.count} value(s) -> {args.output}",
              file=sys.stderr)
    return EXIT_FINDINGS if result.count and args.fail_on_findings else EXIT_CLEAN


def cmd_plan(args: argparse.Namespace) -> int:
    text = sys.stdin.read()
    out = redact_plan_text(text, token=args.token)
    sys.stdout.write(out)
    if not out.endswith("\n") and text.endswith("\n"):
        sys.stdout.write("\n")
    return EXIT_CLEAN


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        target = args.path
        if os.path.isfile(target):
            result = audit_file(target)
        elif os.path.isdir(target):
            result = audit_dir(target)
        else:
            print(f"tfredact: not found: {target}", file=sys.stderr)
            return EXIT_ERROR
    except AuditError as exc:
        print(f"tfredact: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = [f for f in result.findings if f.secret_type]
    summary = result.summary()

    if args.json:
        render_audit_json(summary, findings, out=sys.stdout)
    else:
        render_audit_text(summary, findings, out=sys.stdout, no_color=args.no_color)

    if not findings:
        return EXIT_CLEAN
    return EXIT_FINDINGS if args.fail_on_findings else EXIT_CLEAN


class CLIError(Exception):
    """Raised for CLI-level input problems."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tfredact",
        description=(
            "Scan Terraform state and plan files for secrets, redact them into "
            "shareable copies, and audit sensitive = true coverage."
        ),
    )
    parser.add_argument("--version", action="version", version=f"tfredact {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser(
        "scan", help="scan state files, plan files and plan console output",
        description="Scan for secrets. Exits 1 when anything is found.",
    )
    scan.add_argument("paths", nargs="+",
                      help="files or directories to scan")
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    scan.add_argument("--strict", action="store_true",
                      help="alias for --fail-on-findings (kept for CI ergonomics)")
    scan.add_argument("--fail-on-findings", action="store_true", default=True,
                      help="exit 1 when findings exist (default)")
    scan.add_argument("--no-fail", dest="fail_on_findings", action="store_false",
                      help="report findings but always exit 0")
    scan.add_argument("--min-confidence", choices=["high", "medium", "low"],
                      default="low", help="hide findings below this confidence")
    scan.add_argument("--include-missing", action="store_true",
                      help="do not fail when a path does not exist")
    scan.set_defaults(func=cmd_scan)

    redact = sub.add_parser(
        "redact",
        help="write a shareable copy with secrets replaced by markers",
        description=(
            "Rewrite a state or plan JSON file, replacing every detected secret "
            "with [REDACTED:type] while preserving structure."
        ),
    )
    redact.add_argument("path", help="input .tfstate / plan JSON file")
    redact.add_argument("-o", "--output", help="output path (default: stdout)")
    redact.add_argument("--in-place", action="store_true",
                        help="overwrite the input file")
    redact.add_argument("--json", action="store_true", help="emit a JSON report")
    redact.add_argument("--fail-on-findings", action="store_true",
                        help="exit 1 if anything was redacted")
    redact.set_defaults(func=cmd_redact)

    plan = sub.add_parser(
        "plan",
        help="filter terraform plan console output from stdin to stdout",
        description=(
            "Read terraform plan output on stdin and print it with secrets "
            "redacted, ready to paste into a PR comment or ticket."
        ),
    )
    plan.add_argument("--token", default="***REDACTED***",
                      help="replacement token (default: ***REDACTED***)")
    plan.set_defaults(func=cmd_plan)

    audit = sub.add_parser(
        "audit",
        help="check .tf files for missing sensitive = true and hardcoded secrets",
        description=(
            "Audit HCL for variables and outputs that hold secrets but are not "
            "declared sensitive = true, and for literal secrets inside resource "
            "blocks."
        ),
    )
    audit.add_argument("path", help="a .tf file or a directory of .tf files")
    audit.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    audit.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    audit.add_argument("--fail-on-findings", action="store_true", default=True,
                       help="exit 1 when issues exist (default)")
    audit.add_argument("--no-fail", dest="fail_on_findings", action="store_false",
                       help="report issues but always exit 0")
    audit.set_defaults(func=cmd_audit)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        if getattr(args, "strict", False):
            args.fail_on_findings = True
        return int(args.func(args))
    except CLIError as exc:
        print(f"tfredact: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("tfredact: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except (StateError, PlanError, AuditError, RedactError) as exc:
        print(f"tfredact: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
