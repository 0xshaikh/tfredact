"""tfredact -- scan Terraform state & plan files for secrets, redact them,
and audit ``sensitive = true`` coverage.

Public API. Import these directly for programmatic use; ``tfredact.cli`` is the
command-line entry point.
"""

from __future__ import annotations

from .detectors import (
    Detector,
    Finding,
    VALUE_DETECTORS,
    classify_value,
    detect_in_string,
    shannon_entropy,
)
from .hcl import AuditResult, audit_dir, audit_file
from .plan import redact_plan_text, scan_plan_text, scan_tfplan_json
from .redact import redact_state, redact_state_file, redact_tfplan_json
from .state import scan_state

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # detectors
    "Detector",
    "Finding",
    "VALUE_DETECTORS",
    "classify_value",
    "detect_in_string",
    "shannon_entropy",
    # scanning
    "scan_state",
    "scan_plan_text",
    "scan_tfplan_json",
    # redaction
    "redact_state",
    "redact_state_file",
    "redact_tfplan_json",
    "redact_plan_text",
    # audit
    "AuditResult",
    "audit_file",
    "audit_dir",
]
