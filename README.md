# tfredact

**Find secrets in Terraform state and plan output, redact them into copies you can
actually share, and audit `sensitive = true` coverage.**

A single Python CLI, zero runtime dependencies, no daemon, no side effects.

![scan](docs/img/scan-state.png)

---

## Why this exists

Terraform state files are the most reliable place a production credential ends up
before it is rotated. `tfstate` is designed to be a faithful record of what is
running, so if your database password, IAM secret key or API token is wired in
wrongly, it is in there — full value, no hashing, no truncation.

The usual workflow then makes the problem worse. You need a second opinion, so
you paste the state into a ticket, or email it to a teammate, or drop it in a
PR comment for review. At that moment the secret has moved from one location you
control to three locations you do not.

`tfredact` exists to make that workflow safe without changing it.

## Install

```console
pip install tfredact
```

No dependencies. Python 3.9+. Nothing to configure, no API key, no network
access at runtime — it only reads the files you point it at.

From source:

```console
git clone https://github.com/0xshaikh/tfredact
cd tfredact
pip install -e .
python -m pytest tests -q     # 71 tests, stdlib + pytest only
```

## Quick start

```console
$ tfredact scan state.tfstate
 tfredact  state.tfstate
────────────────────────────────────────────────────────────────────────
 ✗ 32 secret(s) found across 18 type(s)
────────────────────────────────────────────────────────────────────────
 ● random_password            random_password.db_master
     value: R7#mQ2xL...3hAe
     detector: resource_type  [marked sensitive — still stored in state]
 ● aws_access_key_id          aws_iam_access_key.app_db_user
     value: AKIAIOSF...MPLE
     detector: aws_access_key_id  [NOT marked sensitive]
 ● connection_string          aws_secretsmanager_secret_version.appdb_credentials[appdb]
     value: postgres...uire
     detector: connection_string  [marked sensitive — still stored in state]
 ● base64_encoded_blob        aws_instance.app_worker
     value: IyEvYmlu...IDAK
     detector: base64_decode  [NOT marked sensitive]
────────────────────────────────────────────────────────────────────────
 scanned 11 resources / 11 instances
 26 marked sensitive · 6 NOT marked sensitive
────────────────────────────────────────────────────────────────────────
```

### 1. `scan` — what is in here?

```console
tfredact scan <paths>
```

Accepts files and directories. Recognises `*.tfstate`, `terraform.tfstate.*`,
`*.tfplan` and free-form `terraform plan` console logs. Each finding reports the
resource address, the attribute path, the detected type and whether Terraform
had marked it sensitive.

Values are shown as a preview — first and last few characters — so a report is
safe to paste into a ticket even unredacted. Use `--json` for machine output.

### 2. `redact` — give me a copy I can share

```console
$ tfredact redact state.tfstate -o state.redacted.tfstate
tfredact: redacted 32 value(s) -> state.redacted.tfstate
```

The redacted file is a **structurally identical** copy: same resource tree, same
instance counts, same attribute keys, valid JSON. Only the secret values are
replaced with markers like `[REDACTED:password]`. A `_redaction` block records
what the tool did. Diffs, tooling and human review all still work — you just
can't read the credential out of it.

```console
$ git diff state.tfstate state.redacted.tfstate | head
-      "master_user_password": "Pr0d!AppDb2026#Secure",
+      "master_user_password": "[REDACTED:password]",
```

Redaction is idempotent and never mutates the input file. `--in-place` rewrites
the same file instead, which is atomic within a single write but not atomic
across a crash — keep your state backed up, or prefer `-o`.

### 3. `plan` — filter `terraform plan` before it hits the ticket

```console
$ tfredact plan < plan-output.txt > plan-output.redacted.txt
```

Reads `terraform plan` console output on stdin, writes redacted output on
stdout, preserving every line. Line numbers, resource headers, `+`/`~` symbols,
the summary line and all non-secret values survive, so you can still read the
diff. `terraform plan | tfredact plan` works as a pipe filter.

### 4. `audit` — stop the next leak at the config

```console
$ tfredact audit .
 tfredact audit  1 .tf file(s) scanned, 13 block(s)
────────────────────────────────────────────────────────────────────────
 ✗ examples/main.tf:45  variable database_password
     variable holds a secret-looking value but is not declared sensitive = true;
     terraform will print it in cleartext.
     type: string
 ✗ examples/main.tf:53  variable ssh_private_key
     variable holds a secret-looking value but is not declared sensitive = true;
     terraform will print it in cleartext.
     type: string
 ────────────────────────────────────────────────────────────────────────
 6 issue(s): 0 hardcoded, 6 unmarked
────────────────────────────────────────────────────────────────────────
```

Two classes of finding:

- **unmarked** — a `variable` or `output` whose name suggests a secret but which
  is not declared `sensitive = true`. These print in cleartext during
  `terraform plan` and `terraform output -json`.
- **hardcoded** — a resource attribute whose name suggests a secret and whose
  value is a literal string rather than a reference to a variable.

Parses brace-balanced text, so no HCL parser dependency and no Terraform binary
needed.

## What it detects

| Type | Examples |
|---|---|
| `aws_access_key_id` / `aws_secret_access_key` | `AKIA...`, `ASIA...`, `wJalr...` |
| `aws_service_account_blob` | Google-style `{"type":"service_account",...}` |
| `azure_service_principal` | `{"clientId":...,"clientSecret":...}` |
| `google_api_key` / `google_oauth_token` | `AIza...`, `ya29...` |
| `github_pat` / `gitlab_pat` / `gitlab_runner_token` | `ghp_...`, `github_pat_...`, `glpat-...`, `GLPAT-...` |
| `openai_api_key` | `sk-...`, `sk-proj-...` |
| `stripe_secret_key` / `sendgrid_key` / `mailgun_key` / `twilio_credential` | `sk_live_...`, `SG....`, `key-...` |
| `slack_token` / `slack_webhook_url` / `digitalocean_token` | `xoxb-...`, `https://hooks.slack.com/...`, `dop_v1_...` |
| `jwt` | `eyJ...eyJ...sig` |
| `connection_string` | `postgres://user:pass@host/db`, `mongodb+srv://...`, `server=..;password=..` |
| `private_key_pem` / `ssh_private_key` / `certificate_pem` | `-----BEGIN RSA PRIVATE KEY-----` |
| `encrypted_password` | `v1:...`, `v2:...` (RDS KMS-wrapped) |
| `gpg_fingerprint` / `jwt` variants | `-----BEGIN PGP PUBLIC KEY BLOCK-----` |
| `api_token` / `secret_value` / `key_material` | typed by resource and attribute name |
| `password` / `random_password` | prefixed *and* prefix-free values like `random_password.result` |
| `env_assignment_secret` | `export TOKEN=...` lines in scripts |
| `bearer_token` | `Authorization: Bearer ...` |
| `base64_encoded_blob` | decoded, then scanned recursively |

Two layers run in a deliberate order:

1. **precise value-shape match** — a real `AKIA...`, PEM header, JWT structure;
2. **context typing** — the attribute name, then the resource type. This is
   what catches a generated credential like `Pr0d!AppDb2026#Secure` that has no
   recognisable prefix at all;
3. **generic entropy**, last resort, never for known non-secret attributes.

`base64_encoded_blob` is not a terminal type: payloads are decoded and the
decoded contents are scanned, so a password hidden inside a user-data script is
found as `env_assignment_secret` at its real offset, not reported once as "some
base64".

## Why it is tuned for precision

A secret scanner you run in CI must not produce false positives. Every
confidently-wrong finding teaches your team to ignore the report, and then the
real ones get ignored too.

The test suite encodes this with a control fixture: `examples/clean.tfstate`
contains deliberately tricky non-secrets — RSA public keys, long ARNs, high
entropy KMS key material, SSH public keys, DSNs with no credentials — and it
must yield exactly zero findings. Every detector added has to survive it.

```console
$ tfredact scan examples/clean.tfstate
 tfredact  examples/clean.tfstate
────────────────────────────────────────────────────────────────────────
 ✓ No secrets detected.
   scanned 11 resources / 11 instances
────────────────────────────────────────────────────────────────────────
```

## CI

```yaml
- name: fail on secrets in state
  run: tfredact scan terraform.tfstate --strict
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | clean |
| `1` | findings |
| `2` | error (bad input, unreadable path) |

`--json` emits a stable schema for aggregation:

```console
$ tfredact scan state.tfstate --json | jq '{total_findings, .reports[0].summary}'
{
  "total_findings": 32,
  "summary": {
    "path": "state.tfstate",
    "state_version": "4",
    "resources_scanned": 11,
    "instances_scanned": 11,
    "findings": 32,
    "marked_sensitive": 26,
    "unmarked_sensitive": 6,
    "by_type": {
      "password": 7,
      "connection_string": 4,
      "aws_access_key_id": 3
    }
  }
}
```

Each finding carries `path`, `type`, `confidence`, `location`, `detector`,
`entropy`, `nested` and a `value_preview` that is safe to paste anywhere.

## Development

```console
python -m pytest tests -q
python tools/make_screenshots.py   # regenerates docs/img/*.png from real runs
```

The `examples/` directory is a fixture pack: `sample.tfstate` with 23 planted
secrets, `clean.tfstate` as the zero-finding control, `plan-output.txt`,
`main.tf`, and `expected-findings.json` as the ground-truth manifest the tests
assert against.

## Honest limits

- It is a scanner, not a policy engine. It will not tell you whether a
  credential is valid, expired or already rotated — that requires calling the
  provider.
- It does not read or modify `state.json` in place unless you pass `--in-place`;
  the default is always to write a new file.
- Detection is pattern-based. It will not find a secret stored under a name and
  shape that looks nothing like a secret, and you cannot make it do so without
  accepting false positives.
- `sensitive = true` is a logging control, not encryption. A secret Terraform
  believes is sensitive is still stored in full in the state file, and this
  tool reports it as such rather than assuming the marker is a fix.

## Contributing

Issues and PRs welcome. The bar for a new detector is that it does not change
the result on `examples/clean.tfstate`.

## License

MIT — see [LICENSE](LICENSE).
