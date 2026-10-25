"""Terraform state-file scanning (``.tfstate`` / ``terraform.tfstate.*``).

Supports state v4 (the current format) and the legacy v3 shape, where
attributes live under ``resources["addr"].primary.attributes`` instead of
``resources[].instances[].attributes``.

Two independent signals are emitted:

* **Secrets** -- values that look like credentials (see :mod:`tfredact.detectors`).
* **Sensitive-mark audit** -- for each detected secret we check whether terraform
  itself marked the attribute path in ``sensitive_attributes``. This surfaces
  both directions of the intent gap: a secret terraform *thinks* is sensitive
  (and therefore only cosmetically redacted in console output) and a secret it
  *did not* flag, which is invisible in ``terraform plan`` entirely.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

from .detectors import Finding, _visit_leaf

__all__ = [
    "StateResource",
    "load_state",
    "iter_resources",
    "scan_state",
    "StateScanResult",
]

_STATE_V4_KEYS = {"version", "terraform_version", "resources"}
_LEGACY_MARKER = "primary"


def load_state(path: str) -> Dict[str, Any]:
    """Load a JSON state file. Raises :class:`StateError` on unreadable input."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise StateError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise StateError(
            f"{path} is not valid JSON: {exc.msg} (line {exc.lineno} col {exc.colno})"
        ) from exc


class StateError(Exception):
    """Raised for unreadable or malformed state input."""


def _resource_address(resource: Dict[str, Any]) -> str:
    """Human-readable address, e.g. ``aws_rds_instance.appdb[\"prod"]``."""
    type_ = resource.get("type", "?")
    name = resource.get("name", "?")
    addr = f"{type_}.{name}"
    module = resource.get("module")
    if module:
        addr = f"{module}.{addr}"
    return addr


def iter_resources(state: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    """Yield resource objects from either v4 or legacy v3 state."""
    resources = state.get("resources")
    if isinstance(resources, list):
        yield from resources
        return
    if isinstance(resources, dict):
        # Legacy v3: {address: {primary: {attributes: {...}}}}
        for address, entry in resources.items():
            if not isinstance(entry, dict):
                continue
            yield {"type": address, "name": address, "mode": "managed",
                   "instances": [{"attributes": entry.get("primary", {})
                                              .get("attributes", {}),
                                    "sensitive_attributes": []}],
                   "_legacy": True,
                   "_address": address}


def _sensitive_paths(instance: Dict[str, Any]) -> frozenset:
    """Normalise ``sensitive_attributes`` to a set of attribute paths.

    State v4 stores these as an array of attribute *paths*, sometimes nested:
    ``[["attributes", "password"], ["attributes", "data", "token"]]``.
    """
    raw = instance.get("sensitive_attributes") or []
    paths: set = set()
    for item in raw:
        if isinstance(item, str):
            paths.add(item)
        elif isinstance(item, (list, tuple)) and item:
            parts = [str(p) for p in item if p is not None]
            if not parts:
                continue
            joined = ".".join(parts)
            paths.add(joined)
            # Also index by the leaf name so nested detection matches.
            paths.add(parts[-1])
    return frozenset(paths)


def _path_parts(path: str) -> List[str]:
    return [p for p in path.split(".") if p]


class StateScanResult:
    """Aggregated output of a state scan."""

    def __init__(self, path: str, version: Optional[str]) -> None:
        self.path = path
        self.version = version
        self.findings: List[Finding] = []
        self.resources_scanned = 0
        self.instances_scanned = 0

    @property
    def secret_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.secret_type != "sensitive_mark_mismatch"]

    @property
    def unmarked(self) -> List[Finding]:
        """Secrets terraform did *not* flag in ``sensitive_attributes``."""
        return [f for f in self.findings if f.extra.get("sensitive_marked") is False]

    @property
    def marked(self) -> List[Finding]:
        """Secrets terraform flagged -- redacted in console only, still in state."""
        return [f for f in self.findings if f.extra.get("sensitive_marked") is True]

    def summary(self) -> Dict[str, Any]:
        from collections import Counter

        counts = Counter(f.secret_type for f in self.secret_findings)
        return {
            "path": self.path,
            "state_version": self.version,
            "resources_scanned": self.resources_scanned,
            "instances_scanned": self.instances_scanned,
            "findings": len(self.secret_findings),
            "by_type": dict(sorted(counts.items())),
            "marked_sensitive": len(self.marked),
            "unmarked_sensitive": len(self.unmarked),
        }


def _walk_attributes(attributes: Any, prefix: str, location: str,
                     sensitive: frozenset, out: List[Finding],
                     seen_paths: set) -> None:
    if not isinstance(attributes, dict):
        return
    for key, value in attributes.items():
        path = f"{prefix}.{key}"
        if path in seen_paths:
            continue
        seen_paths.add(path)

        findings: List[Finding] = []
        _visit_leaf(path, str(key), value, location, findings)

        for finding in findings:
            # ``sensitive_attributes`` records e.g. ``attributes.password``.
            # A nested finding like ``attributes.secret_string.dsn`` is covered
            # when its parent container path is marked.
            parts = _path_parts(finding.path)
            container_paths = {".".join(parts[:i + 1]) for i in range(len(parts))}
            bare = {parts[-1]} if parts else set()
            marked = bool((container_paths | bare) & sensitive) if sensitive else False
            finding.location = location
            finding.extra["sensitive_marked"] = marked
            out.append(finding)


def scan_state(path: str) -> StateScanResult:
    """Scan one state file and return all findings with sensitive-mark context."""
    state = load_state(path)
    result = StateScanResult(path, str(state.get("version", "?")))

    for resource in iter_resources(state):
        if not isinstance(resource, dict):
            continue
        address = resource.get("_address") or _resource_address(resource)
        result.resources_scanned += 1
        for instance in resource.get("instances", []):
            if not isinstance(instance, dict):
                continue
            result.instances_scanned += 1
            sensitive = _sensitive_paths(instance)
            attributes = instance.get("attributes", instance)
            index_key = instance.get("index_key")
            location = address if index_key is None else f"{address}[{index_key}]"
            seen: set = set()
            _walk_attributes(attributes, "attributes", location, sensitive,
                             result.findings, seen)

    _scan_outputs(state, result)
    return result


def _scan_outputs(state: Dict[str, Any], result: StateScanResult) -> None:
    """Root ``outputs`` block: ``terraform output -json`` prints these verbatim."""
    outputs = state.get("outputs")
    if not isinstance(outputs, dict):
        return
    for name, spec in outputs.items():
        value = spec.get("value") if isinstance(spec, dict) else spec
        marked = bool(isinstance(spec, dict) and spec.get("sensitive") is True)
        findings: List[Finding] = []
        _visit_leaf(f"outputs.{name}", str(name), value, "outputs", findings)
        for finding in findings:
            finding.location = "outputs"
            finding.extra["sensitive_marked"] = marked
        result.findings.extend(findings)
