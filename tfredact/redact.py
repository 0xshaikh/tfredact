"""Redact a Terraform state or plan file into a shareable copy.

The point of this module is the workflow everyone reaches for a screenshot of:
"I need to post this state to a GitHub issue / hand it to support / attach it to
a Slack thread, but it contains production database passwords."

:func:`redact_state` walks the JSON and replaces every detected secret with a
deterministic marker while leaving the surrounding structure byte-intact enough
to stay diffable and reviewable. Nothing is dropped, nothing is re-ordered, and
non-secret values are untouched -- so two redacted states of the same cluster
still diff the way the originals would.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .detectors import (
    Finding,
    classify_value,
    is_placeholder,
    parse_structured,
)

__all__ = [
    "redact_state",
    "redact_tfplan_json",
    "marker_for",
    "RedactResult",
]

MARKER_TEMPLATE = "[REDACTED:{secret_type}]"


def marker_for(secret_type: str) -> str:
    return MARKER_TEMPLATE.format(secret_type=secret_type)


class RedactResult:
    """Outcome of a redaction pass."""

    def __init__(self) -> None:
        self.replacements: List[Finding] = []
        self.unredacted_nested = 0

    @property
    def count(self) -> int:
        return len(self.replacements)

    def summary(self, path: str = "") -> Dict[str, object]:
        return {
            "path": path,
            "values_redacted": self.count,
            "redacted_paths": [f.path for f in self.replacements],
        }


def _replace(value: Any, key: str, result: RedactResult, path: str,
             depth: int = 0) -> Tuple[Any, bool]:
    """Return ``(new_value, changed)`` for a single value."""
    if depth > 12:
        return value, False

    # A real nested object (terraform stores some of these natively rather than
    # as string literals): recurse into it, keep the shape for readable diffs.
    if isinstance(value, (dict, list)):
        new_obj, child_count = _replace_container(value, path, result, depth + 1)
        if child_count > 0:
            result.replacements.append(Finding(
                path=path, secret_type="nested_secret_container",
                value=str(value)[:120], detector="nested_object", nested=True,
                extra={"children_redacted": child_count},
            ))
            return new_obj, True
        return value, False

    if not isinstance(value, str):
        return value, False
    if is_placeholder(value):
        return value, False

    wrapped = parse_structured(value)
    if wrapped is not None:
        kind, parsed = wrapped
        if kind == "b64":
            result.replacements.append(Finding(
                path=path, secret_type="base64_encoded_blob", value=value,
                detector="base64_decode", nested=True,
                extra={"decoded_chars": len(parsed) if isinstance(parsed, str) else 0},
            ))
            return marker_for("base64_encoded_blob"), True

        # JSON / dict-literal container: redact the children, keep the shape.
        new_parsed, child_count = _replace_container(parsed, path, result, depth + 1)
        if child_count > 0:
            if kind == "py":
                # Terraform emits these as Python dict/list reprs, so round-trip
                # through repr() to preserve the original encoding.
                new_value = repr(new_parsed)
            else:
                new_value = json.dumps(new_parsed, indent=2, ensure_ascii=False)
            result.replacements.append(Finding(
                path=path, secret_type="nested_secret_container", value=value,
                detector=f"nested_{kind}", nested=True,
                extra={"children_redacted": child_count},
            ))
            return new_value, True
        return value, False

    finding = classify_value(value, key)
    if finding is None:
        return value, False
    result.replacements.append(Finding(
        path=path, secret_type=finding.secret_type, value=value,
        confidence=finding.confidence, detector=finding.detector,
        entropy=finding.entropy,
    ))
    return marker_for(finding.secret_type), True


def _replace_container(obj: Any, path: str, result: RedactResult,
                       depth: int) -> Tuple[Any, int]:
    count = 0
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            child = f"{path}.{k}" if path else str(k)
            replaced, changed = _replace(v, str(k), result, child, depth)
            new[k] = replaced
            if changed:
                count += 1
        return new, count
    if isinstance(obj, list):
        new = []
        for i, v in enumerate(obj):
            child = f"{path}[{i}]"
            replaced, changed = _replace(v, "", result, child, depth)
            new.append(replaced)
            if changed:
                count += 1
        return new, count
    return obj, 0


def _redact_attributes(attributes: Dict[str, Any], path: str, resource: str,
                       result: RedactResult, depth: int) -> Dict[str, Any]:
    if depth > 20 or not isinstance(attributes, dict):
        return attributes
    out = {}
    for key, value in attributes.items():
        key = str(key)
        child = f"{path}.{key}"
        replaced, changed = _replace(value, key, result, child, depth + 1)
        out[key] = replaced
    return out


def redact_state(state: Dict[str, Any],
                 state_path: Optional[str] = None) -> Tuple[Dict[str, Any], RedactResult]:
    """Return a redacted deep copy of ``state`` plus a redaction report."""
    import copy

    result = RedactResult()
    out = copy.deepcopy(state)

    resources = out.get("resources")
    if isinstance(resources, list):
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            type_ = resource.get("type", "?")
            name = resource.get("name", "?")
            module = resource.get("module", "")
            address = f"{module}.{type_}.{name}" if module else f"{type_}.{name}"
            instances = resource.get("instances")
            if isinstance(instances, list):
                for instance in instances:
                    if not isinstance(instance, dict):
                        continue
                    attrs = instance.get("attributes")
                    if isinstance(attrs, dict):
                        instance["attributes"] = _redact_attributes(
                            attrs, "attributes", address, result, 1)
    elif isinstance(resources, dict):
        for address, entry in resources.items():
            if not isinstance(entry, dict):
                continue
            primary = entry.get("primary")
            if isinstance(primary, dict) and isinstance(primary.get("attributes"), dict):
                primary["attributes"] = _redact_attributes(
                    primary["attributes"], "attributes", address, result, 1)

    outputs = out.get("outputs")
    if isinstance(outputs, dict):
        new_outputs = {}
        for name, spec in outputs.items():
            if isinstance(spec, dict):
                value = spec.get("value")
                replaced, _ = _replace(value, str(name), result, f"outputs.{name}", 1)
                spec["value"] = replaced
            else:
                replaced, _ = _replace(spec, str(name), result, f"outputs.{name}", 1)
                spec = replaced
            new_outputs[name] = spec
        out["outputs"] = new_outputs

    out.setdefault("_redaction", {})
    out["_redaction"] = {
        "tool": "tfredact",
        "values_redacted": result.count,
        "marker": MARKER_TEMPLATE,
        "note": ("Values replaced by tfredact. Structure and non-secret values are "
                 "preserved so the file remains diffable."),
    }
    return out, result


def redact_tfplan_json(plan: Dict[str, Any]) -> Tuple[Dict[str, Any], RedactResult]:
    """Redact ``terraform show -json plan`` output.

    Only ``change.after`` is rewritten: that is the value terraform will write to
    state. ``before`` is historical and ``after_unknown`` entries are not values
    yet, so both are left alone to keep the plan readable.
    """
    import copy

    result = RedactResult()
    out = copy.deepcopy(plan)
    changes = out.get("resource_changes")
    if not isinstance(changes, list):
        return out, result
    for change in changes:
        if not isinstance(change, dict):
            continue
        address = change.get("address", "")
        diff = change.get("change")
        if not isinstance(diff, dict):
            continue
        after = diff.get("after")
        after_unknown = set(change.get("after_unknown", []) or [])
        if isinstance(after, dict):
            new_after = {}
            for attr, value in after.items():
                if attr in after_unknown:
                    new_after[attr] = value
                    continue
                if isinstance(value, list) and any(x is None for x in value):
                    new_after[attr] = value
                    continue
                replaced, _ = _replace(value, str(attr), result,
                                       f"change.after.{attr}", 1, )
                new_after[attr] = replaced
            diff["after"] = new_after
    return out, result


def redact_state_file(path: str) -> Tuple[str, RedactResult]:
    """Read a state file, redact it, and return ``(json_text, report)``."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except FileNotFoundError as exc:
        raise RedactError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RedactError(
            f"{path} is not valid JSON: {exc.msg} (line {exc.lineno} col {exc.colno})"
        ) from exc
    redacted, result = redact_state(state)
    return json.dumps(redacted, indent=2, ensure_ascii=False) + "\n", result


class RedactError(Exception):
    """Raised for unreadable redaction input."""
