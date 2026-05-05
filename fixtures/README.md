# tf-analyze golden fixtures

Each subdirectory is a small Terraform snippet that intentionally triggers one
or more catalogue findings. They serve as **regression tests for the skill
itself** — when the skill runs in `mode:self-test` it scans every fixture and
asserts the expected catalogue IDs appear (and no unexpected ones).

| Fixture | Expected catalogue IDs |
|---|---|
| `iam_too_broad/` | `SEC-IAM-001` |
| `missing_prevent_destroy/` | `ROB-LIFECYCLE-001`, `ROB-LIFECYCLE-002` |
| `wide_provider_constraint/` | `SEC-PROVIDER-001` |
| `no_validation_blocks/` | `ROB-VALIDATION-001`, `ROB-VALIDATION-002` |
| `public_bucket/` | `SEC-IAM-002`, `SEC-BUCKET-001`, `SEC-BUCKET-002` |
| `sensitive_leak/` | `SEC-SENSITIVE-001`, `SEC-SENSITIVE-002` |
| `audit_logs_missing/` | `SEC-LOGGING-001` |
| `cloudsql_no_backup/` | `STK-CLOUDSQL-001` |
| `unpinned_module/` | `MOD-PIN-001` |

## Running the fixtures manually

```bash
cd <fixture-dir>
terraform init -backend=false
terraform validate
```

Each fixture must `validate` cleanly so the skill reads it as intended Terraform
(not parse-broken HCL). The fixtures are deliberately tiny so the skill's
analysis pass is fast and the expected findings are unambiguous.

## Running the self-test

```bash
# Invokes the skill with mode:self-test, scoped to fixtures/
/tf-analyze mode:self-test
```

The self-test passes if every expected ID is detected and no unexpected ID
appears. Failures are reported per fixture.

## Adding a new fixture

1. Pick the catalogue IDs the fixture should trigger. If a needed ID does not
   yet exist, add the catalogue entry first under `catalog/` (see
   `catalog/README.md`).
2. Create a directory named after the failure mode.
3. Add the smallest possible `.tf` file that triggers exactly those IDs.
4. Add the fixture's expected IDs to the table above.
5. Add the fixture name to the `fixtures:` list of every catalogue entry it
   exercises.
6. Run `mode:self-test` and confirm pass.
