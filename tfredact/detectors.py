"""Secret detection primitives for tfredact.

Two detection layers work together:

1. **Value detectors** -- regexes anchored on a *value's* own shape
   (`AKIA...`, `ghp_...`, `postgres://u:p@host`, PEM headers). These are
   precise: a match means "this string literally looks like a credential".

2. **Attribute-key context** -- a Terraform attribute *named* ``password`` or
   ``secret_key`` is a secret even when its value has no recognisable prefix
   (a generated 24-character password has no marker at all). This is the layer
   that catches the majority of real-world state leaks.

The two layers are reconciled by :func:`classify_value`: a precise value match
always wins over a generic entropy match, and a meaningful key-name hint wins
over a generic entropy match but not over a precise value match.

Detection is deliberately conservative on purpose. Every rule here is a
false-positive hazard, so high-precision anchors and word boundaries are used
throughout. The one generic rule (entropy) is gated behind a length floor and a
strict charset and is never allowed to override a specific detector.
"""

from __future__ import annotations

import base64
import collections
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

__all__ = [
    "Finding",
    "Detector",
    "VALUE_DETECTORS",
    "SECRET_KEY_HINTS",
    "EXCLUDED_KEY_HINTS",
    "PLACEHOLDER_VALUES",
    "shannon_entropy",
    "classify_value",
    "detect_in_string",
    "is_base64_blob",
    "is_placeholder",
    "is_excluded_key",
    "leaf_detectors",
    "decode_base64",
    "parse_structured",
    "redact_display",
]

HIGH = "high"
MEDIUM = "medium"
LOW = "low"


@dataclass
class Finding:
    """A single detected secret.

    ``path`` is a JSON-ish path into the document, e.g.
    ``attributes.master_user_password`` or ``resources[3].instances[0].attributes``.
    ``location`` is a human-readable provenance string (resource address,
    ``file:line``, ...) rendered separately from the path.

    Not frozen on purpose: scanners enrich findings as they descend, setting
    ``location``/``confidence``/``extra`` after construction.
    """

    path: str
    secret_type: str
    value: str
    confidence: str = HIGH
    location: str = ""
    detector: str = ""
    entropy: Optional[float] = None
    nested: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def preview(self) -> str:
        return redact_display(self.value)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character. 0.0 for empty input."""
    if not text:
        return 0.0
    counts = collections.Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# --------------------------------------------------------------------------
# Value detectors
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Detector:
    """A value-shape rule: a secret type, a confidence and a compiled regex.

    ``text_only`` rules are only run against free-form text (plan console
    output, logs), never against individual JSON leaf values. Assignment-shaped
    rules like ``KEY=value`` are useful on a plan line but fire on unrelated
    substrings inside structured values, so they are quarantined here.
    """

    secret_type: str
    confidence: str
    pattern: str
    text_only: bool = False
    _re: Optional[re.Pattern] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "_re", re.compile(self.pattern))

    def match(self, text: str) -> Optional[str]:
        m = self._re.search(text)
        return m.group(0) if m else None

    def iter_matches(self, text: str) -> Iterable[tuple]:
        return ((m, m.group(0)) for m in self._re.finditer(text))


# Rules applied to every leaf value in state / plan JSON.
def leaf_detectors() -> Iterable[Detector]:
    return (d for d in VALUE_DETECTORS if not d.text_only)


# Anchors: the trailing ``\b`` matters. Without it, ``AKIA`` inside a longer
# uppercase run (an AWS tag value, a build id) would match.
# The optional ``(?:\.{3}...)?`` tail accepts Terraform's own abbreviated
# rendering of keys, e.g. ``AKIAIO...MPLE`` / ``ghp_7A...B9cD`` -- terraform
# truncates long values in plan output, and a scanner that refuses to read them
# would miss the most-cited leak shape in the wild.
_DOTTED = r"(?:\.{3}[A-Za-z0-9]{2,})?"


VALUE_DETECTORS: Sequence[Detector] = (
    Detector(
        "aws_access_key_id", HIGH,
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{2,}" + _DOTTED + r"\b",
    ),
    Detector(
        "github_pat", HIGH,
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{2,}" + _DOTTED + r"\b",
    ),
    Detector(
        "github_pat", HIGH,
        r"\bgithub_pat_[A-Za-z0-9_]{2,}" + _DOTTED + r"\b",
    ),
    Detector(
        "github_pat", HIGH,
        r"\bghus_[A-Za-z0-9_]{2,}" + _DOTTED + r"\b",
    ),
    Detector(
        "google_api_key", HIGH,
        r"\bAIza[0-9A-Za-z\-_]{8,}" + _DOTTED + r"\b",
    ),
    Detector(
        "google_oauth_token", MEDIUM,
        r"\bya29\.[0-9A-Za-z_\-]{10,}",
    ),
    Detector(
        "openai_api_key", HIGH,
        r"\bsk-(?:proj-)?[A-Za-z0-9]{12,}\b",
    ),
    Detector(
        "stripe_secret_key", HIGH,
        r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{12,}\b",
    ),
    Detector(
        "stripe_webhook_secret", HIGH,
        r"\bwhsec_[0-9a-zA-Z]{12,}\b",
    ),
    Detector(
        "slack_token", HIGH,
        r"\bxox[baprs]-[A-Za-z0-9\-]{6,}",
    ),
    Detector(
        "slack_webhook_url", HIGH,
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{8,}",
    ),
    Detector(
        "gitlab_pat", HIGH,
        r"\bglpat-[0-9a-zA-Z_\-]{12,}\b",
    ),
    Detector(
        "gitlab_runner_token", HIGH,
        r"\bGR[0-9a-fA-F]{8,}\b",
    ),
    Detector(
        "digitalocean_token", HIGH,
        r"\bdop_v1_[A-Za-z0-9]{12,}\b",
    ),
    Detector(
        "sendgrid_key", HIGH,
        r"\bSG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}\b",
    ),
    Detector(
        "mailgun_key", HIGH,
        r"\bkey-[a-zA-Z0-9]{24,}\b",
    ),
    Detector(
        "twilio_credential", HIGH,
        r"\b(?:SK|AC)[0-9a-fA-F]{24,}\b",
    ),
    Detector(
        "gpg_fingerprint", HIGH,
        r"\bpgp-?sha256:[A-Za-z0-9+/]{40,}={0,2}\b",
    ),
    Detector(
        "jwt", HIGH,
        r"\beyJ[A-Za-z0-9_\-]{8,}" + _DOTTED + r"(?:\.[A-Za-z0-9_\-]{6,}(?:\.[A-Za-z0-9_\-]{2,})?)?\b",
    ),
    Detector(
        "private_key_pem", HIGH,
        r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----",
    ),
    Detector(
        "certificate_pem", MEDIUM,
        r"-----BEGIN\s+CERTIFICATE-----",
    ),
    Detector(
        "ssh_private_key", HIGH,
        r"-----BEGIN\s+(?:OPENSSH|PGP)\s+PRIVATE\s+KEY(?:\s+BLOCK)?-----",
    ),
    Detector(
        "connection_string", HIGH,
        r"postgres(?:ql)?://[^:\s/@\"']+:[^@\s\"']+@",
    ),
    Detector(
        "connection_string", HIGH,
        r"\b(?:mysql|mysql\+trilogy|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|sqlserver|"
        r"clickhouse|tidb|elasticsearch)://[^:\s/@\"']+:[^@\s\"']+@",
    ),
    Detector(
        "bearer_token", MEDIUM,
        r"\bBearer\s+[A-Za-z0-9_.\-]{20,}",
    ),
    Detector(
        "bearer_token", MEDIUM,
        r"\bAuthorization:\s*Bearer\s+[A-Za-z0-9_.\-]{20,}",
    ),
    Detector(
        "aws_service_account_blob", HIGH,
        r"(?i)\"type\"\s*:\s*\"service_account\"",
    ),
    Detector(
        "azure_service_principal", HIGH,
        r"(?i)\"clientSecret\"\s*:\s*\"[^\"]{8,}\"",
    ),
    Detector(
        "bearer_token", MEDIUM,
        r"\bAuthorization:\s*Bearer\s+[A-Za-z0-9_.\-]{20,}",
        text_only=True,
    ),
    # ``export FOO=bar`` / ``FOO: bar`` assignments inside cloud-init user_data,
    # scripts and plan heredocs. Terraform's own tutorial shows kube_config
    # leaking this way through a user_data script.
    #
    # Deliberately strict. The key must be an ALL-CAPS identifier: a lowercase
    # ``secret:`` inside an ARN (``arn:aws:secretsmanager:...:secret:foo``)
    # must not match, and neither must a URL path or a JSON object key.
    Detector(
        "env_assignment_secret", MEDIUM,
        r"\b[A-Z][A-Z0-9_]{2,}(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|"
        r"KEY|PASSPHRASE|CREDENTIAL|AUTH)[A-Z0-9_]{0,20}\s*[=:]\s*"
        r"['\"]?([A-Za-z0-9_\-./+=!@#$%^&*]{8,})",
        text_only=True,
    ),
)

# The generic rule. Deliberately the last entry and deliberately narrow:
# 24+ characters, strict alnum charset, no punctuation (so connection strings
# and scripts never trip it), and entropy >= 4.0 bits. A URL path or an AMI id
# does not satisfy this; a 32-character generated credential does.
_GENERIC_RE = re.compile(r"[A-Za-z0-9/+=]{24,}")
GENERIC_MIN_LEN = 24
GENERIC_MIN_ENTROPY = 4.0


def _entropy_fallback(text: str) -> Optional[str]:
    """Scan for generic high-entropy runs, longest first."""
    best: Optional[tuple] = None
    for m in _GENERIC_RE.finditer(text):
        chunk = m.group(0)
        # Trim run-length artefacts: a repeat tail like ``aaa...`` deflates entropy.
        ent = shannon_entropy(chunk)
        if len(chunk) >= GENERIC_MIN_LEN and ent >= GENERIC_MIN_ENTROPY:
            if best is None or len(chunk) > len(best[1]):
                best = (ent, chunk)
    return best[1] if best else None


# --------------------------------------------------------------------------
# Attribute-key context
# --------------------------------------------------------------------------

# Ordered. First match wins, so specific names come before their substrings
# (`encrypted_password` before `password`, `secret_access_key` before `secret`).
SECRET_KEY_HINTS: Sequence[tuple] = (
    # AWS IAM
    ("secret_access_key", "aws_secret_access_key"),
    ("secret_key", "aws_secret_access_key"),
    ("aws_secret", "aws_secret_access_key"),
    ("secret_key_id", "aws_access_key_id"),
    ("access_key", "aws_access_key_id"),
    # Write-only args never reach state -- explicit early skip handled separately.
    ("encrypted_password", "encrypted_password"),
    ("master_user_password", "password"),
    ("certificate_password", "password"),
    ("passphrase", "password"),
    ("password", "password"),
    ("pwd", "password"),
    # Tokens
    # More specific names must come first: matching is on token boundaries, so
    # ``slack_webhook_token`` ends with the generic ``webhook_token`` needle.
    ("slack_webhook_token", "slack_webhook_url"),
    ("slack_webhook_url", "slack_webhook_url"),
    ("api_token", "api_token"),
    ("webhook_token", "api_token"),
    ("github_pat", "github_pat"),
    ("github_token", "github_pat"),
    ("gh_token", "github_pat"),
    ("openai", "openai_api_key"),
    ("stripe_secret", "stripe_secret_key"),
    ("whsec", "stripe_webhook_secret"),
    ("access_token", "token"),
    ("refresh_token", "token"),
    ("session_token", "token"),
    ("auth_token", "token"),
    ("auth_pass", "token"),
    ("slack_webhook", "slack_webhook_url"),
    ("slack_token", "slack_token"),
    ("webhook_url", "slack_webhook_url"),
    ("slack_url", "slack_webhook_url"),
    # Keys / certs
    ("private_key", "private_key_pem"),
    ("client_key", "private_key_pem"),
    ("client_certificate", "private_key_pem"),
    ("cluster_ca_certificate", "private_key_pem"),
    ("key_material", "key_material"),
    ("ssl_certificate", "certificate_pem"),
    ("tls_certificate", "certificate_pem"),
    ("certificate_body", "certificate_pem"),
    ("certificate", "certificate_pem"),
    ("client_secret", "client_secret"),
    ("tenant_secret", "client_secret"),
    # Vaults / blobs
    ("secret_string", "secret_string_blob"),
    ("secret_binary", "secret_string_blob"),
    ("secret_value", "secret_value"),
    ("secrets_bundle", "secret_string_blob"),
    ("credential", "credential_blob"),
    ("credentials", "credential_blob"),
    ("secret", "secret_string_blob"),
    # Connection strings
    ("connection_string", "connection_string"),
    ("jdbc_uri", "connection_string"),
    ("dsn", "connection_string"),
    ("uri", "connection_string"),
    ("endpoint_uri", "connection_string"),
    ("redis_url", "connection_string"),
)

# Attribute names that look secret-ish but are not. Getting these wrong is the
# main way a scanner earns a reputation for noise, so the exclusion list is
# explicit rather than inferred.
EXCLUDED_KEY_HINTS = frozenset({
    "public_key", "ssh_public_key", "public_keys", "authorized_key",
    "key_id", "secret_key_id", "key_fingerprint", "key_algorithm", "key_spec",
    "key_usage", "key_state", "key_arn", "key_material_exportable", "key_policy",
    "key_name", "key_name_prefix", "key_names", "key_source", "key_origin",
    "key_ids", "pgp_key", "pgp_key_id", "key_ripemd256", "key_md5",
    "key_sha1", "key_sha256", "key_sha512", "ssh_user", "ssh_keys",
    "certificate_id", "certificate_arn", "certificate_name",
    "certificate_domain_names", "certificate_authority_id",
    "ca_cert_identifier", "ca_certificate_id",
    "key_version", "kms_key_id", "kms_key_arn", "kms_key_alias_name",
    "secret_arn", "secret_name", "secret_id", "secret_aws_account_id",
    "secret_version_id", "secret_versions", "secret_versions_stages",
    "recovery_window_in_days",
    "secret_string_wo", "password_wo", "master_user_password_wo",
    "username", "master_username", "db_username", "admin_username",
    "user_name", "account_id", "owner_id",
    "tags", "tags_all", "name", "description", "id", "arn", "type",
    "status", "enabled", "state", "engine", "family", "region",
    "availability_zone", "zone", "endpoint", "address", "hostname",
    "private_ip", "public_ip", "ip_address", "ip_addresses",
    "subnet_id", "vpc_id", "security_groups", "vpc_security_group_ids",
    "security_group_id", "security_group_name",
    "instance_id", "instance_type", "instance_class",
    "ami", "ami_id", "image_id", "kernel_id", "ramdisk_id",
    "snapshot_id", "volume_id",
    "role_arn", "policy_arn", "profile", "profile_arn",
    "provider", "version", "serial", "lineage", "schema_version",
    "depends_on", "dependencies", "index_key", "mode",
    "create_date", "created_date", "created_time", "create_time",
    "update_date", "updated_date", "end_of_life", "beginning_of_life",
    "version_id", "stages", "replication_status",
    "deletion_protection", "delete_snapshot_on_destroy",
    "allocated_storage", "port", "port_range", "cidr_blocks", "cidr",
    "from_port", "to_port", "prefix_list_ids", "ip_protocol",
    "user_data_replace_on_change", "user_data_replace_on_create",
    "metadata", "parameter", "parameters", "parameter_groups",
    "data_json", "data", "conflict", "ignore_missing", "no_merge",
    "max_versions", "enable_response_wrapping", "disable_migration",
    "disable_read", "disable_write", "path",
})

# Attribute names that must not trigger the generic entropy rule either. An
# exclusion here means "this attribute is known to hold non-secret material",
# so falling back to entropy would only manufacture false positives -- the
# classic case being an ssh-ed25519 *public* key, which is high-entropy by
# construction.
EXCLUDED_FOR_ENTROPY = frozenset({
    *EXCLUDED_KEY_HINTS,
    "key", "id", "hash", "fingerprint", "checksum", "digest",
    "encoded", "encoded_json", "encoded_compressed_json", "md5", "sha1",
    "sha256", "ripemd256", "base64", "base64sha256", "url_hash",
    "block_id", "source_hash", "etag", "revision",
})

# Names whose values terraform writes as JSON / python-repr / base64 containers.
# These are judged by their children, never by the container itself.
_CONTAINER_KEYS = frozenset({"data", "data_json"})

# Attributes that hold base64-encoded *payloads* rather than base64-encoded
# scalars. These are always unwrapped and their decoded contents scanned.
_BLOB_KEYS = frozenset({
    "user_data", "user_data_base64", "secret_binary", "encoded", "encoded_json",
    "encoded_compressed_json", "value_base64", "blob", "body", "payload",
    "certificate_body_base64", "private_key_pem_base64", "content_base64",
})

# Attribute names are not enough on their own: ``secret`` on an
# ``aws_iam_access_key`` is an AWS secret access key, but ``secret`` on anything
# else is usually a generic secret blob. When the resource type makes the
# meaning unambiguous, prefer that over the generic table.
RESOURCE_TYPE_KEY_HINTS: Dict[str, Dict[str, str]] = {
    "aws_iam_access_key": {
        "secret": "aws_secret_access_key",
        "secret_key": "aws_secret_access_key",
        "id": "aws_access_key_id",
        "key_id": "aws_access_key_id",
        "secret_key_id": "aws_access_key_id",
    },
    "aws_iam_user": {
        "password": "password",
        "sensitive_password": "password",
    },
    "random_password": {"result": "random_password"},
    "random_string": {"result": "random_string"},
    "random_id": {"result": "random_string"},
    "random_uuid": {"result": "random_string"},
    "aws_secretsmanager_secret_version": {
        "secret_string": "secret_string_blob",
        "secret_binary": "secret_string_blob",
        "secret_value": "secret_value",
    },
    "aws_secretsmanager_secret_version_stages": {
        "secret_value": "secret_value",
    },
    "aws_db_instance": {
        "master_user_password": "password",
        "password": "password",
        "db_instance_password": "password",
    },
    "tls_private_key": {
        "private_key_pem": "private_key_pem",
        "private_key_openssh": "private_key_pem",
        "private_key": "private_key_pem",
    },
    "aws_ec2_key_pair": {"key_material": "private_key_pem"},
    "aws_acm_certificate": {"certificate_body": "certificate_pem"},
}

# Values that are clearly not secrets even when the attribute name looks like
# one. Terraform persists explicit nulls as the literal string ``None``.
PLACEHOLDER_VALUES = frozenset({
    "", "None", "null", "NULL", "N/A", "na", "n/a", "-", "--",
    "changeme", "change_me", "changeme!", "changeme123",
    "todo", "TODO", "fixme", "FIXME",
    "placeholder", "PLACEHOLDER", "replace-me", "replace_me", "replace",
    "example", "EXAMPLE", "sample", "SAMPLE", "dummy", "DUMMY",
    "test", "TEST", "your-key-here", "your_key_here", "your-key",
    "redacted", "REDACTED", "[REDACTED]", "<redacted>", "***",
    "[REDACTED PRIVATE KEY]",
    "00000000-0000-0000-0000-000000000000",
})

# ``password_wo`` / ``secret_string_wo`` are write-only arguments. By design they
# never persist to state, so they must not be reported.
_WRITE_ONLY_SUFFIX = "_wo"


_PLACEHOLDER_WORDS = re.compile(
    r"redact|placeholder|changeme|change_me|todo|fixme|dummy|"
    r"replace|skel|unset|test123|hunter2|xxx+|fake|mock|tbd|pending|\bn/a\b|\bna\b",
    re.IGNORECASE,
)
# ``example`` and ``sample`` are deliberately NOT in the list above. AWS's own
# documentation keys are shaped exactly like real credentials
# (``AKIAIOSFODNN7EXAMPLE`` / ``wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY``), and
# a real deployment that copy-pastes a doc value is still a real finding.
# Filtering on the word would have been convenient and wrong.
# Braced/template placeholders: ``(redacted)``, ``<redacted>``, ``${VAR}``,
# ``{{ secret }}``, ``[REDACTED PRIVATE KEY]``.
_PLACEHOLDER_BRACED = re.compile(r"^[<[{\[][^<>[\]{}]{0,40}[>]}]\]]$")


def _key_hint(name: str) -> Optional[str]:
    """Return the secret type implied by an attribute name, or None.

    Matching is on token boundaries, not raw substrings. Terraform attributes
    are underscore-delimited, and a plain substring test is what turns
    ``security_group_id`` into a connection string (``se**curi**ty`` contains
    ``uri``). Tokens are joined with ``_`` before comparison.
    """
    if not name:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not normalized:
        return None
    if normalized in EXCLUDED_KEY_HINTS or normalized.endswith(_WRITE_ONLY_SUFFIX):
        return None
    if normalized in _CONTAINER_KEYS:
        # Container attributes: judged by their children, not by themselves.
        return None

    for needle, secret_type in SECRET_KEY_HINTS:
        needle_norm = re.sub(r"[^a-z0-9]+", "_", needle.lower()).strip("_")
        if not needle_norm:
            continue
        # needle must cover the name exactly, or start/end on a token boundary.
        pattern = rf"(?:^|_){re.escape(needle_norm)}(?=$|_)"
        if re.search(pattern, normalized):
            return secret_type
    return None


def is_excluded_key(name: str) -> bool:
    """True if ``name`` is a known non-secret attribute (public keys, ids, ...)."""
    if not name:
        return False
    normalized = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return normalized in EXCLUDED_FOR_ENTROPY


def resource_key_hint(resource_type: str, key: str) -> Optional[str]:
    """Type a key from its resource type, falling back to None.

    Called before the generic attribute-name table. ``result`` on
    ``random_password`` and ``secret`` on ``aws_iam_access_key`` are only
    interpretable with the resource type in hand.
    """
    if not key or not resource_type:
        return None
    table = RESOURCE_TYPE_KEY_HINTS.get(resource_type)
    if not table:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
    return table.get(normalized)


def is_placeholder(value: str) -> bool:
    """True if ``value`` is empty, a terraform null, or a known placeholder."""
    if value is None:
        return True
    stripped = value.strip()
    if not stripped:
        return True
    if stripped in PLACEHOLDER_VALUES:
        return True
    if len(stripped) <= 3 and set(stripped) <= {"*"}:
        return True
    if _PLACEHOLDER_WORDS.search(stripped):
        return True
    if _PLACEHOLDER_BRACED.match(stripped):
        return True
    if len(stripped) < 6:
        # Anything this short is below the minimum a generated credential
        # reaches; treat as non-secret rather than guess.
        return True
    return False


def _is_write_only(name: str) -> bool:
    return bool(name) and name.lower().endswith(_WRITE_ONLY_SUFFIX)


# --------------------------------------------------------------------------
# Structured-value unwrapping
# --------------------------------------------------------------------------

_JSON_BLOB_RE = re.compile(r"^\s*(\{.*\}|\[.*\])\s*$", re.DOTALL)
_PY_REPR_RE = re.compile(r"^\s*([{\[].*[}\]])\s*$", re.DOTALL)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{24,}={0,2}$")


def _try_json(text: str):
    import json

    try:
        return json.loads(text)
    except Exception:
        return None


def _try_py_repr(text: str):
    import ast

    try:
        return ast.literal_eval(text)
    except Exception:
        return None


def parse_structured(text: str):
    """Return ``(kind, parsed)`` if a string value actually wraps a structure.

    Terraform state v4 serialises collections of nested attributes as strings
    (vault ``data`` is a Python dict repr; ``secret_string`` is a JSON blob;
    ``user_data`` is base64). A scanner that only looks at leaf values misses
    every secret stored in one of these containers.
    """
    if not isinstance(text, str) or len(text) < 3:
        return None
    if _JSON_BLOB_RE.match(text):
        parsed = _try_json(text)
        if parsed is not None and isinstance(parsed, (dict, list)):
            return "json", parsed
        parsed = _try_py_repr(text)
        if parsed is not None and isinstance(parsed, (dict, list)):
            return "py", parsed
        return None
    if _PY_REPR_RE.match(text):
        parsed = _try_py_repr(text)
        if parsed is not None and isinstance(parsed, (dict, list)):
            return "py", parsed
    if _B64_RE.match(text):
        decoded = decode_base64(text)
        if decoded is not None:
            return "b64", decoded
    return None


def decode_base64(text: str) -> Optional[str]:
    """Best-effort base64 decode. Returns str, or None when not a real blob."""
    try:
        padding = "=" * (-len(text) % 4)
        raw = base64.b64decode(text + padding, validate=False)
        decoded = raw.decode("utf-8", errors="strict")
    except Exception:
        return None
    if len(decoded) < 4:
        return None
    # Printable-rate check: a random base64 blob decodes to mostly garbage.
    printable = sum(1 for ch in decoded if ch == "\n" or ch == "\t" or 32 <= ord(ch) < 127)
    if printable / len(decoded) < 0.85:
        return None
    if "\x00" in decoded:
        return None
    return decoded


def is_base64_blob(text: str) -> bool:
    return parse_structured(text) is not None and parse_structured(text)[0] == "b64"


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------

_GENERIC_TYPES = {"high_entropy_token"}


_CREDENTIAL_DSN_RE = re.compile(
    r"[a-z][a-z0-9+]*://[^:/\s@\"']{1,64}:[^@\s\"']{1,256}@", re.IGNORECASE
)


def _has_embedded_credentials(value: str) -> bool:
    """True if a DSN contains a ``scheme://user:password@`` userinfo component."""
    return bool(_CREDENTIAL_DSN_RE.search(value))


def _dsn_scheme(value: str) -> Optional[str]:
    """Extract the URI scheme from a DSN, or None when there is none."""
    m = re.match(r"\s*([a-z][a-z0-9+]*)://", value, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _annotate(finding: Finding) -> None:
    """Attach value-derived metadata so a Finding is self-describing.

    Callers of ``classify_value`` alone (as opposed to the walker) still get a
    complete Finding, so reports are stable regardless of entry point.
    """
    if finding.secret_type == "connection_string":
        scheme = _dsn_scheme(finding.value)
        if scheme:
            finding.extra["scheme"] = scheme


def classify_value(value: str, key: str = "", resource_type: str = "") -> Optional[Finding]:
    """Classify one scalar string value. Returns None when nothing is secret.

    Precedence is deliberate:

    1. a precise value-shape match (a real ``AKIA...`` / PEM / JWT literal),
    2. typing from the resource type, then from the attribute name,
    3. generic entropy, last resort and never for known non-secret attributes.
    """
    if not isinstance(value, str) or is_placeholder(value):
        return None

    # 1. Precise value detectors (shape-based, independent of the attribute name).
    for detector in leaf_detectors():
        matched = detector.match(value)
        if matched:
            finding = Finding(
                path="",
                secret_type=detector.secret_type,
                value=value,
                confidence=detector.confidence,
                detector=detector.secret_type,
                entropy=shannon_entropy(matched),
                extra={"matched": matched},
            )
            _annotate(finding)
            return finding

    if key:
        typed = resource_key_hint(resource_type, key) if resource_type else None
        if typed is None and key not in _CONTAINER_KEYS:
            typed = _key_hint(key)
        if typed is not None and not _is_write_only(key):
            if typed == "connection_string" and not _has_embedded_credentials(value):
                # A DSN with no embedded password is infrastructure info, not a
                # secret. There is nothing here to redact.
                return None
            finding = Finding(
                path="",
                secret_type=typed,
                value=value,
                confidence=MEDIUM,
                detector="resource_type" if typed == resource_key_hint(resource_type, key)
                else "attribute_name",
                entropy=shannon_entropy(value),
            )
            _annotate(finding)
            return finding

    # 3. Generic entropy, last resort. Skipped for attributes that are known to
    # hold non-secret material (public keys, ids, hashes).
    if is_excluded_key(key):
        return None
    generic = _entropy_fallback(value)
    if generic is not None:
        return Finding(
            path="",
            secret_type="high_entropy_token",
            value=generic,
            confidence=LOW,
            detector="entropy",
            entropy=shannon_entropy(generic),
        )
    return None


def detect_in_string(text: str, key: str = "") -> Optional[Finding]:
    """Alias of :func:`classify_value`, kept for call-site clarity."""
    return classify_value(text, key)


def _iter_structured(obj, path: str, resource: str, out: List[Finding],
                     depth: int = 0, max_depth: int = 8) -> None:
    """Recursively visit string leaves inside a wrapped container."""
    if depth > max_depth:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path else str(k)
            _visit_leaf(child, str(k), v, resource, out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _visit_leaf(f"{path}[{i}]", "", v, resource, out, depth + 1)
    else:
        _visit_leaf(path, "", obj, resource, out, depth + 1)


def _resource_type(resource: str) -> str:
    """Extract the terraform resource type from an address like ``aws_rds_instance.appdb``."""
    if not resource or resource.startswith("outputs"):
        return ""
    return resource.split(".", 1)[0]


def _typed_hint(resource: str, key: str) -> Optional[str]:
    """Secret type for ``key``, preferring resource-type context over name heuristics."""
    if not key:
        return None
    specific = resource_key_hint(_resource_type(resource), key)
    if specific is not None:
        return specific
    if key in _CONTAINER_KEYS:
        return None
    return _key_hint(key)


def _visit_leaf(path: str, key: str, value, resource: str, out: List[Finding],
                depth: int = 0) -> None:
    if isinstance(value, (dict, list)):
        _iter_structured(value, path, resource, out, depth, 8)
        return
    if not isinstance(value, str):
        return

    wrapped = parse_structured(value)
    if wrapped is not None:
        kind, parsed = wrapped
        hint = _typed_hint(resource, key)

        # Base64 is incidental encoding, not containment. ``key_material`` is a
        # base64 string, but it is one scalar secret -- typing it as a blob would
        # lose the fact that it is a KMS key. Only treat a base64 value as a
        # container when its attribute name does not already name the secret,
        # or when the name is a known blob-holding attribute.
        if kind == "b64" and hint is not None and key.lower() not in _BLOB_KEYS:
            finding = classify_value(value, key, _resource_type(resource))
            if finding is not None:
                finding.path = path
                finding.location = resource
                finding.extra["encoding"] = "base64"
                finding.extra["decoded_chars"] = len(parsed) if isinstance(parsed, str) else 0
                out.append(finding)
            return

        if kind == "b64":
            # Decode and scan the payload: this is where cloud-init user_data
            # and secretsmanager blobs hide their real contents.
            decoded = parsed if isinstance(parsed, str) else ""
            nested: List[Finding] = []
            for detector in VALUE_DETECTORS:
                for _m, matched in detector.iter_matches(decoded):
                    if len(matched) < 8:
                        continue
                    nested.append(Finding(
                        path=f"{path}::decoded", secret_type=detector.secret_type,
                        value=matched, confidence=detector.confidence,
                        detector=detector.secret_type, location=resource,
                        nested=True,
                    ))
            finding = Finding(
                path=path, secret_type="base64_encoded_blob", value=value,
                confidence=MEDIUM if nested else LOW, location=resource,
                detector="base64_decode", entropy=shannon_entropy(value),
                nested=True,
                extra={
                    "decoded_preview": decoded[:80].replace("\n", "\\n"),
                    "decoded_chars": len(decoded),
                    "nested_findings": len(nested),
                    "nested_types": sorted({n.secret_type for n in nested}),
                },
            )
            out.append(finding)
            out.extend(nested)
            return

        # JSON / dict-literal container: recurse first, and only report the
        # container itself when it actually contains a secret. A kms policy or
        # an empty vault record would otherwise be reported as a "blob" leak.
        children: List[Finding] = []
        _iter_structured(parsed, path, resource, children, depth + 1, 8)
        if children:
            out.append(Finding(
                path=path, secret_type="secret_string_blob", value=value,
                confidence=MEDIUM, location=resource, detector=f"nested_{kind}",
                entropy=shannon_entropy(value),
                nested=True,
                extra={"children_findings": len(children)},
            ))
            out.extend(children)
        return

    finding = classify_value(value, key, _resource_type(resource))
    if finding is not None:
        finding.path = path
        finding.location = resource
        out.append(finding)


def redact_display(value: str, keep: int = 8) -> str:
    """Truncate a value for display without echoing it in full."""
    if not isinstance(value, str):
        return ""
    if "\n" in value:
        value = value.split("\n", 1)[0]
    if len(value) <= keep * 2:
        return value
    return f"{value[:keep]}...{value[-4:]}"


def all_detectors() -> Iterable[Detector]:
    return VALUE_DETECTORS
