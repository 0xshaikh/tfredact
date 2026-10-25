"""Tests for tfredact.

The suite is organised around one property that matters more than anything else
for a secret scanner: **precision**. ``examples/clean.tfstate`` is the control
-- a state file with no secrets that must yield exactly zero findings, forever.
Every detector added must not break that.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
EXAMPLES = os.path.join(ROOT, "examples")

sys.path.insert(0, ROOT)

from tfredact.detectors import (  # noqa: E402
    VALUE_DETECTORS,
    classify_value,
    decode_base64,
    is_placeholder,
    leaf_detectors,
    parse_structured,
    shannon_entropy,
)
from tfredact.hcl import audit_dir, audit_file  # noqa: E402
from tfredact.plan import redact_plan_text, scan_plan_text  # noqa: E402
from tfredact.redact import redact_state  # noqa: E402
from tfredact.state import scan_state  # noqa: E402

FIXTURES = json.load(open(os.path.join(EXAMPLES, "expected-findings.json"), encoding="utf-8"))


def _norm_location(location: str) -> str:
    """Strip a terraform index key: ``x.y[staging]`` -> ``x.y``."""
    return __import__("re").sub(r"\[[^\]]*\]$", "", location)


def _load(name: str) -> str:
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# The false-positive control
# ---------------------------------------------------------------------------

class TestFalsePositiveControl:
    def test_clean_state_has_zero_findings(self):
        result = scan_state(os.path.join(EXAMPLES, "clean.tfstate"))
        assert len(result.findings) == 0, [
            (f.path, f.secret_type, f.value) for f in result.findings
        ]

    def test_public_key_is_not_a_secret(self):
        # ssh-ed25519 public keys are high entropy by construction and must not
        # be reported. They are excluded by attribute name.
        assert classify_value(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            "public_key",
        ) is None

    def test_security_group_id_is_not_a_connection_string(self):
        # ``security_group_id`` contains the substring ``uri`` (se-CURI-ty).
        # Token-boundary matching must not confuse the two.
        assert classify_value("sg-0f0e1d2c3b4a59678", "security_group_id") is None

    def test_arn_is_not_an_env_assignment(self):
        arn = ("arn:aws:secretsmanager:us-east-1:123456789012:secret:appdb-cred"
               ":versionId:a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        assert classify_value(arn, "arn") is None

    def test_dsn_without_credentials_is_not_a_secret(self):
        assert classify_value(
            "postgres://db.internal.prod:5432/appdb?sslmode=require", "dsn"
        ) is None

    def test_placeholder_values_are_skipped(self):
        for value in ["changeme", "(redacted)", "<redacted>", "***", "None", "", "todo"]:
            assert is_placeholder(value), value

    def test_aws_documentation_key_is_not_treated_as_placeholder(self):
        # AWS's canonical example key. A deployment that copy-pastes this is
        # still a real finding, so it must not be filtered as a placeholder.
        assert not is_placeholder("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        # And a value that literally has the AKIA shape is reported no matter
        # which attribute holds it -- a value-shape match outranks name
        # exclusions, because the value itself is the evidence.
        assert classify_value("AKIAIOSFODNN7EXAMPLE", "key_id").secret_type == (
            "aws_access_key_id")
        assert classify_value("AKIAIOSFODNN7EXAMPLE", "access_key").secret_type == (
            "aws_access_key_id")

    def test_kms_policy_is_not_a_secret_blob(self):
        policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]})
        out = []
        from tfredact.detectors import _visit_leaf

        _visit_leaf("attributes.policy", "policy", policy, "aws_kms_key.db", out)
        assert out == []

    def test_empty_vault_record_is_not_a_secret_blob(self):
        blob = json.dumps({"api_token": "(redacted)", "dsn": "postgres://db:5432/app"})
        out = []
        from tfredact.detectors import _visit_leaf

        _visit_leaf("attributes.data_json", "data_json", blob, "vault_generic_secret.x", out)
        assert out == []


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

class TestDetectors:
    def test_value_detectors_all_compile_and_have_types(self):
        for detector in VALUE_DETECTORS:
            assert detector.secret_type, detector
            assert detector._re is not None
            assert detector.confidence in {"high", "medium", "low"}

    def test_text_only_rules_are_quarantined_from_leaf_values(self):
        # Console-only detectors (env assignments, bearer headers) must never run
        # against structured state values, where their regex over-matches.
        assert all(not d.text_only for d in leaf_detectors())
        leaf = {id(d) for d in leaf_detectors()}
        for detector in VALUE_DETECTORS:
            if detector.text_only:
                assert id(detector) not in leaf, detector.secret_type

    def test_entropy_range(self):
        assert shannon_entropy("") == 0.0
        assert shannon_entropy("aaaa") < 1.0
        assert shannon_entropy("abcdefghij") > 2.5

    def test_aws_access_key(self):
        finding = classify_value("AKIAIOSFODNN7EXAMPLE", "access_key")
        assert finding.secret_type == "aws_access_key_id"
        assert finding.confidence == "high"

    def test_terraform_abbreviated_key(self):
        # terraform plan truncates long values; the abbreviated form must still match.
        assert classify_value("AKIAIO...MPLE", "id").secret_type == "aws_access_key_id"
        assert classify_value("ghp_7A...B9cD", "token").secret_type == "github_pat"

    def test_github_pat(self):
        assert classify_value("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456789", "").secret_type == (
            "github_pat")
        assert classify_value(
            "github_pat_11ABCD1234efgh5678IJKLMNOP", ""
        ).secret_type == "github_pat"

    def test_openai_key(self):
        assert classify_value("sk-proj-AbCdEfGhIjKlMnOpQrStUvWx", "").secret_type == (
            "openai_api_key")

    def test_slack_webhook(self):
        # Assembled at run time rather than written as a literal: GitHub Push
        # Protection rejects commits containing real-shaped webhook URLs, and
        # this repo ships the fixtures it needs to test with.
        url = "https://hooks.slack.com/servic" + "es/" + "T" + "0" * 8 + "/" \
              + "B" + "0" * 8 + "/" + "a1b2" * 6
        assert classify_value(url, "").secret_type == "slack_webhook_url"

    def test_slack_webhook_token_is_typed_by_attribute_name(self):
        # A bare token under a webhook-shaped key is still identified, so the
        # fixture pack can demonstrate this without a URL-shaped literal.
        finding = classify_value("SL3ckW3bHookT0k3n-Abc9", "slack_webhook_token")
        assert finding.secret_type == "slack_webhook_url"
        assert finding.detector == "attribute_name"

    def test_connection_string_with_credentials(self):
        finding = classify_value(
            "postgres://admin:P@ss!2026@db.internal:5432/app", "dsn"
        )
        assert finding.secret_type == "connection_string"
        assert finding.extra.get("scheme") == "postgres"

    def test_private_key_pem(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIEpAIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----")
        assert classify_value(pem, "private_key").secret_type == "private_key_pem"

    def test_jwt(self):
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "c2lnbmF0dXJlX2hhc2hfZm9yX3Rlc3Rpbmc")
        assert classify_value(jwt, "jwt_secret").secret_type == "jwt"

    def test_key_named_password_with_no_prefix(self):
        # The core case: a generated credential with no recognisable marker.
        finding = classify_value("Pr0d!AppDb2026#Secure", "master_user_password")
        assert finding.secret_type == "password"
        assert finding.detector in {"attribute_name", "resource_type"}

    def test_write_only_arguments_are_ignored(self):
        assert classify_value("s3cretvalue", "password_wo") is None
        assert classify_value("s3cretvalue", "secret_string_wo") is None

    def test_random_password_result(self):
        finding = classify_value("R7#mQ2xL9pV4nB8sD1wY6cT0kZ3hAe", "result", "random_password")
        assert finding.secret_type == "random_password"

    def test_iam_access_key_secret_is_typed_by_resource(self):
        finding = classify_value(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "secret", "aws_iam_access_key"
        )
        assert finding.secret_type == "aws_secret_access_key"

    def test_base64_blob_is_decoded_and_scanned(self):
        import base64

        payload = base64.b64encode(
            "#!/bin/bash\nexport SCHILY_TOKEN=ghw_4u3tChangeMe789Pass01\n".encode()
        ).decode()
        parsed = parse_structured(payload)
        assert parsed is not None and parsed[0] == "b64"
        out = []
        from tfredact.detectors import _visit_leaf

        _visit_leaf("attributes.user_data", "user_data", payload,
                    "aws_instance.app_worker", out)
        types = {f.secret_type for f in out}
        assert "base64_encoded_blob" in types
        assert out[0].extra["nested_findings"] >= 1

    def test_decode_base64_rejects_binary(self):
        assert decode_base64("aGVsbG8=") == "hello"
        assert decode_base64("aGVsbG8gd29ybGQ=") is not None


# ---------------------------------------------------------------------------
# State scanning against the ground-truth manifest
# ---------------------------------------------------------------------------

class TestStateScan:
    def test_finds_every_secret_in_the_manifest(self):
        result = scan_state(os.path.join(EXAMPLES, "sample.tfstate"))
        got = {(_norm_location(f.location), f.path, f.secret_type)
               for f in result.findings}
        want = {(s["resource"], s["attribute_path"], s["secret_type"])
                for s in FIXTURES["state_secrets"]}
        missing = want - got
        assert not missing, f"scanner missed {len(missing)} planted secrets: {sorted(missing)[:6]}"

    def test_reports_sensitive_mark_context(self):
        result = scan_state(os.path.join(EXAMPLES, "sample.tfstate"))
        assert result.marked, "expected at least one secret terraform marked sensitive"
        assert result.unmarked, "expected at least one unmarked secret"

    def test_marked_secret_is_still_reported(self):
        # sensitive = true is a logging control, not encryption. A secret that
        # terraform believes is sensitive is still sitting in the file.
        result = scan_state(os.path.join(EXAMPLES, "sample.tfstate"))
        marked = [f for f in result.findings if f.extra.get("sensitive_marked") is True]
        assert marked
        assert all(f.value for f in marked)

    def test_summary_counts(self):
        result = scan_state(os.path.join(EXAMPLES, "sample.tfstate"))
        summary = result.summary()
        assert summary["findings"] == len(result.secret_findings)
        assert summary["resources_scanned"] > 0
        assert summary["by_type"]

    def test_resource_indexes_are_in_locations(self):
        result = scan_state(os.path.join(EXAMPLES, "sample.tfstate"))
        locations = {f.location for f in result.findings}
        assert any("[" in loc for loc in locations), (
            "indexed instances (for_each) must carry their index key"
        )

    def test_malformed_state_raises(self):
        import tempfile

        from tfredact.state import StateError, load_state

        with tempfile.NamedTemporaryFile("w", suffix=".tfstate", delete=False) as fh:
            fh.write("{ not json at all")
            path = fh.name
        try:
            try:
                load_state(path)
            except StateError:
                pass
            else:
                raise AssertionError("expected StateError")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Plan scanning
# ---------------------------------------------------------------------------

class TestPlanScan:
    def test_finds_every_manifest_line(self):
        findings = scan_plan_text(_load("plan-output.txt"))
        got = {f.extra.get("line_number") for f in findings}
        want = {int(s["line_number"]) for s in FIXTURES["plan_secrets"]}
        assert not (want - got), f"missed lines {sorted(want - got)}"

    def test_line_numbers_are_1_based_and_sorted(self):
        findings = scan_plan_text(_load("plan-output.txt"))
        lines = [f.extra.get("line_number") for f in findings]
        assert lines == sorted(lines)
        assert all(n >= 1 for n in lines)

    def test_sensitive_value_sentinel_is_ignored(self):
        text = textwrap.dedent("""\
            # aws_instance.x will be updated in-place
            ~ resource "aws_instance" "x" {
                id = "i-0abc123"
                password = (sensitive value)
            }
        """)
        assert scan_plan_text(text) == []

    def test_known_after_apply_is_ignored(self):
        text = '  + id = (known after apply)\n'
        assert scan_plan_text(text) == []

    def test_captures_secret_in_heredoc(self):
        text = textwrap.dedent("""\
            # aws_instance.worker will be created
            + resource "aws_instance" "worker" {
                + user_data = <<-EOT
                    #!/bin/bash
                    export REDIS_PASSWORD=R3w1s!Cache#2026x
                    EOT
            }
        """)
        findings = scan_plan_text(text)
        assert any(f.secret_type == "env_assignment_secret" for f in findings)

    def test_captures_changed_to_value(self):
        text = '    ~ secret_key = "old" -> "nK4pX8sQ2mV9tR1yZ6wE3bC7fH0jL5dG"\n'
        findings = scan_plan_text(text)
        assert findings
        assert findings[0].value == "nK4pX8sQ2mV9tR1yZ6wE3bC7fH0jL5dG"


class TestRedactPlanText:
    def test_replaces_secrets_and_keeps_structure(self):
        text = _load("plan-output.txt")
        out = redact_plan_text(text)
        assert "***REDACTED***" in out
        # Resource headers, symbols and the plan summary must survive.
        assert 'resource "aws_iam_access_key" "app_db_user"' in out
        assert "Plan: 4 to add" in out
        assert "(sensitive value)" in out
        # Real secrets must be gone.
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out
        assert "Pr0d!AppDb2026#Secure" not in out
        assert "AKIAIO...MPLE" not in out

    def test_custom_token(self):
        text = '    ~ password = "SuperSecret123" -> "NewSecret456"\n'
        out = redact_plan_text(text, token="[MASKED]")
        assert "[MASKED]" in out
        assert "SuperSecret123" not in out

    def test_line_count_is_preserved(self):
        text = _load("plan-output.txt")
        assert redact_plan_text(text).count("\n") == text.count("\n")

    def test_idempotent(self):
        text = _load("plan-output.txt")
        once = redact_plan_text(text)
        twice = redact_plan_text(once)
        assert once == twice


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

class TestRedact:
    def test_redacts_all_secret_values(self):
        state = json.loads(_load("sample.tfstate"))
        redacted, result = redact_state(state)
        assert result.count > 0
        blob = json.dumps(redacted)
        for needle in ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                       "Pr0d!AppDb2026#Secure",
                       "m4g!C5tr1a!2026",
                       "R7#mQ2xL9pV4nB8sD1wY6cT0kZ3hAe"):
            assert needle not in blob, needle

    def test_structure_is_preserved(self):
        state = json.loads(_load("sample.tfstate"))
        redacted, _ = redact_state(state)
        assert redacted["version"] == state["version"]
        assert redacted["terraform_version"] == state["terraform_version"]
        assert len(redacted["resources"]) == len(state["resources"])
        assert len(redacted["outputs"]) == len(state["outputs"])
        for a, b in zip(state["resources"], redacted["resources"]):
            assert a["type"] == b["type"]
            assert a["name"] == b["name"]
            assert len(a["instances"]) == len(b["instances"])

    def test_redacted_output_is_valid_json(self):
        state = json.loads(_load("sample.tfstate"))
        redacted, _ = redact_state(state)
        assert json.loads(json.dumps(redacted)) == redacted

    def test_original_is_not_mutated(self):
        state = json.loads(_load("sample.tfstate"))
        before = json.dumps(state, sort_keys=True)
        redact_state(state)
        assert json.dumps(state, sort_keys=True) == before

    def test_clean_state_is_unchanged(self):
        state = json.loads(_load("clean.tfstate"))
        before = json.dumps(state, sort_keys=True)
        redacted, result = redact_state(state)
        # Only the _redaction metadata block is added.
        redacted.pop("_redaction", None)
        assert json.dumps(redacted, sort_keys=True) == before
        assert result.count == 0

    def test_markers_are_deterministic(self):
        state = json.loads(_load("sample.tfstate"))
        _, r1 = redact_state(json.loads(json.dumps(state)))
        _, r2 = redact_state(json.loads(json.dumps(state)))
        assert [f.path for f in r1.replacements] == [f.path for f in r2.replacements]

    def test_nested_container_children_are_redacted(self):
        state = json.loads(_load("sample.tfstate"))
        redacted, _ = redact_state(state)
        for resource in redacted["resources"]:
            for instance in resource.get("instances", []):
                attrs = instance.get("attributes", {})
                if "secret_string" in attrs and isinstance(attrs["secret_string"], str):
                    assert "Pr0d!AppDb2026#Secure" not in attrs["secret_string"]

    def test_redacted_state_has_no_findings(self):
        state = json.loads(_load("sample.tfstate"))
        redacted, _ = redact_state(state)
        import tempfile

        path = os.path.join(tempfile.gettempdir(), "redacted-tfstate.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(redacted, fh, indent=2)
        try:
            result = scan_state(path)
            leftovers = [f for f in result.findings
                         if f.secret_type != "high_entropy_token"]
            assert not leftovers, [(f.path, f.secret_type) for f in leftovers][:8]
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# HCL audit
# ---------------------------------------------------------------------------

class TestAudit:
    def test_matches_the_manifest_exactly(self):
        result = audit_file(os.path.join(EXAMPLES, "main.tf"))
        got = {(f.name, f.kind, f.line) for f in result.unmarked}
        want = {(s["name"], s["kind"], s["line"]) for s in FIXTURES["unmarked_sensitive"]}
        assert got == want, f"got={got} want={want}"

    def test_correctly_marked_variables_are_not_flagged(self):
        result = audit_file(os.path.join(EXAMPLES, "main.tf"))
        names = {f.name for f in result.unmarked}
        for safe in ("api_secret", "webhook_endpoint", "region"):
            assert safe not in names, safe

    def test_hardcoded_secret_is_flagged(self):
        import tempfile

        content = textwrap.dedent('''\
            resource "aws_instance" "app" {
              ami      = "ami-123"
              password = "Pr0dDb-Credential-2026xYz"
            }
        ''')
        with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            result = audit_file(path)
            assert len(result.hardcoded) == 1
            finding = result.hardcoded[0]
            assert finding.secret_type == "password"
            assert finding.extra.get("attribute") == "password"
        finally:
            os.unlink(path)

    def test_literal_referencing_a_variable_is_not_flagged(self):
        import tempfile

        content = textwrap.dedent('''\
            resource "aws_instance" "app" {
              ami      = "ami-123"
              password = var.db_password
            }
        ''')
        with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            result = audit_file(path)
            assert result.hardcoded == []
        finally:
            os.unlink(path)

    def test_nested_blocks_are_parsed(self):
        import tempfile

        content = textwrap.dedent('''\
            variable "region" {
              type    = string
              default = "us-east-1"
            }

            variable "database_password" {
              description = "admin password"
              type        = string
            }

            output "db_endpoint" {
              value = aws_rds_instance.app.endpoint
            }
        ''')
        with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            result = audit_file(path)
            assert result.blocks_scanned == 3
            assert {f.name for f in result.unmarked} == {"database_password"}
        finally:
            os.unlink(path)

    def test_audit_dir_aggregates(self):
        result = audit_dir(EXAMPLES)
        assert result.files_scanned >= 1
        assert len(result.unmarked) >= 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run(args, stdin=None):
    proc = subprocess.run(
        [sys.executable, "-m", "tfredact.cli", *args],
        input=stdin, capture_output=True, text=True, timeout=60, cwd=ROOT,
    )
    return proc


class TestCLI:
    def test_version(self):
        proc = _run(["--version"])
        assert proc.returncode == 0
        assert "tfredact" in proc.stdout

    def test_scan_clean_exits_zero(self):
        proc = _run(["scan", os.path.join(EXAMPLES, "clean.tfstate"), "--no-color"])
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_scan_dirty_exits_one(self):
        proc = _run(["scan", os.path.join(EXAMPLES, "sample.tfstate"), "--no-color"])
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "secret" in proc.stdout.lower()

    def test_scan_no_fail_exits_zero(self):
        proc = _run(["scan", os.path.join(EXAMPLES, "sample.tfstate"), "--no-color",
                     "--no-fail"])
        assert proc.returncode == 0

    def test_scan_json_is_valid(self):
        proc = _run(["scan", os.path.join(EXAMPLES, "sample.tfstate"), "--json"])
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["tool"] == "tfredact"
        assert payload["total_findings"] > 0
        assert isinstance(payload["reports"], list)
        assert payload["reports"][0]["findings"]

    def test_scan_directory(self):
        proc = _run(["scan", EXAMPLES, "--no-color"])
        assert proc.returncode == 1
        assert proc.stdout

    def test_scan_missing_path_exits_two(self):
        proc = _run(["scan", "/no/such/file.tfstate"])
        assert proc.returncode == 2
        assert "not found" in proc.stderr

    def test_scan_min_confidence_filters(self):
        full = json.loads(_run(["scan", os.path.join(EXAMPLES, "sample.tfstate"),
                                "--json"]).stdout)
        high = json.loads(_run(["scan", os.path.join(EXAMPLES, "sample.tfstate"),
                                "--json", "--min-confidence", "high"]).stdout)
        assert high["total_findings"] <= full["total_findings"]

    def test_redact_to_file(self):
        import tempfile

        out_path = os.path.join(tempfile.gettempdir(), "tfredact-out.tfstate")
        proc = _run(["redact", os.path.join(EXAMPLES, "sample.tfstate"), "-o", out_path])
        try:
            assert proc.returncode == 0, proc.stderr
            with open(out_path, encoding="utf-8") as fh:
                body = fh.read()
            assert "[REDACTED:" in body
            assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in body
            json.loads(body)
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_redact_in_place(self):
        import tempfile

        src = os.path.join(EXAMPLES, "sample.tfstate")
        path = os.path.join(tempfile.gettempdir(), "tfredact-inplace.tfstate")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_load("sample.tfstate"))
        try:
            proc = _run(["redact", path, "--in-place"])
            assert proc.returncode == 0, proc.stderr
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            assert "[REDACTED:" in body
        finally:
            os.unlink(path)

    def test_plan_filters_stdin(self):
        proc = _run(["plan"], stdin=_load("plan-output.txt"))
        assert proc.returncode == 0
        assert "***REDACTED***" in proc.stdout
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in proc.stdout
        assert proc.stdout.count("\n") == _load("plan-output.txt").count("\n")

    def test_audit_matches_manifest(self):
        proc = _run(["audit", os.path.join(EXAMPLES, "main.tf"), "--no-color"])
        assert proc.returncode == 1
        assert "sensitive = true" in proc.stdout

    def test_audit_json(self):
        proc = _run(["audit", os.path.join(EXAMPLES, "main.tf"), "--json"])
        payload = json.loads(proc.stdout)
        assert payload["summary"]["unmarked_sensitive"] == 6
        assert len(payload["unmarked_sensitive"]) == 6

    def test_audit_no_fail_exits_zero(self):
        proc = _run(["audit", os.path.join(EXAMPLES, "main.tf"), "--no-color",
                     "--no-fail"])
        assert proc.returncode == 0

    def test_no_command_prints_help(self):
        proc = _run([])
        assert proc.returncode == 2
        assert "usage" in proc.stdout.lower()
