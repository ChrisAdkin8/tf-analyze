# tf-analyze finding catalogue

Stable finding identifiers used across runs of the skill. Each entry is a single
YAML file. The filename is the canonical ID.

## ID format

```
<DOMAIN>-<SUBDOMAIN>-<NNN>
```

| Domain | Meaning |
|---|---|
| `SEC` | Security |
| `ROB` | Robustness |
| `DRY` | DRY / code reuse |
| `STY` | Style |
| `SIM` | Simplicity |
| `OPS` | Operational readiness |
| `CCD` | CI/CD and testing |
| `MOD` | Cross-module contracts |
| `STK` | Stack-specific (Vault, Consul, GKE, Helm) |
| `VER` | CLAUDE.md verification |

`<SUBDOMAIN>` is a short kebab tag (e.g., `IAM`, `LIFECYCLE`, `LOGGING`). `<NNN>`
is a zero-padded sequence within the subdomain.

**IDs are stable across skill runs and across skill versions.** Once an ID is
allocated it must never be repurposed. Deprecated findings should be marked
`status: deprecated` rather than deleted, so historical reports remain
interpretable.

## Schema

```yaml
id: SEC-GCP-IAM-001              # required, must match filename (without .yaml)
title: "Short human title"   # required, ≤80 chars
section: security            # required, one of: security|robustness|dry|style|simplicity|ops|cicd|module|stack|verification
default_urgency: HIGH        # required, one of: CRITICAL|HIGH|MEDIUM|LOW|INFO
blast_radius: module         # required, one of: single-resource|module|environment|infrastructure-wide
status: active               # optional, default active. one of: active|deprecated|experimental
cis:                         # optional, list of CIS GCP v4.0 control IDs
  - "1.6"
patterns:                    # required, ≥1. detection patterns the skill applies.
  - kind: resource_arg       # one of: resource_arg|resource_missing_arg|resource_present|grep|hcl_attr
    resource: google_project_iam_member
    arg: role
    regex: "^roles/(owner|editor|.*Admin)$"
recommendation: |            # required, multiline. recommended fix.
  Replace with `google_storage_bucket_iam_member` (or equivalent
  resource-level binding from Appendix A) and grant the narrowest
  role the workload requires.
verification: |              # required, multiline. how to verify the fix landed.
  After applying the fix, run `terraform plan` and confirm the
  project-level binding is destroyed and the resource-level binding
  is created. Re-run tf-analyze in mode:verify-fixed.
related: []                  # optional, list of related catalogue IDs
escalation:                  # optional, conditions that bump urgency
  - condition: "estimated_monthly_cost_usd > 1000"
    new_urgency: HIGH
fixtures:                    # optional, list of fixture directories that exercise this finding
  - iam_too_broad
```

## Pattern kinds

Per-file kinds (run inside `detect_in_file`):

| Kind | Meaning |
|---|---|
| `resource_arg` | A `resource` block whose argument matches a regex |
| `resource_missing_arg` | A `resource` block of the named type that lacks the named argument. Supports an optional `suppress_if: { arg: X, equals: "val" }` field — the finding is suppressed when an alternative arg equals the specified value (e.g., SQS queue encrypted via `sqs_managed_sse_enabled = true` suppresses the `kms_master_key_id` missing check). |
| `resource_present` | Any `resource` block of the named type triggers the finding |
| `data_source_present` | Any `data` block of the named type triggers the finding (e.g. `vault_kv_secret_v2`) |
| `grep` | A regex against the raw file body — last resort, use sparingly |
| `hcl_attr` | A specific HCL nested-block attribute path (e.g., `lifecycle.prevent_destroy`) |
| `moved_block_present` | TF 1.5+ `moved` block — flagged for cleanup once apply has run |
| `removed_block_present` | TF 1.7+ `removed` block — flagged for cleanup once destroy has run |
| `count_index_ref`, `count_bool_pattern`, `count_length_unguarded`, `count_foreach_mix` | `count`/`for_each` anti-patterns |
| `variable_missing_validation`, `variable_missing_description`, `variable_type` | Variable hygiene |
| `output_missing_description` | Output hygiene |

Corpus-level kinds (run inside `detect_corpus` once per scan):

| Kind | Meaning |
|---|---|
| `resource_absent` | Fires when a resource type is **absent** from the scan target. Use `when_present: <type>` to guard against cross-cloud false positives (only fires when the prerequisite type exists). Use `scope: repo` for repo-wide absence checks. |
| `backend_missing_arg` | Fires when a `terraform { backend "<type>" {} }` block is missing a required argument (e.g., S3 backend without `dynamodb_table`). Fields: `backend_type`, `arg`. |
| `providers_version_missing` | Fires once per `required_providers` provider entry that has no `version` constraint. Used by `ROB-VERSION-003`. No extra fields needed — the kind scans all files. |
| `output_sensitive_leak`, `cross_module`, `variable_unused`, `output_unused`, `module_missing_tests`, `backend_inconsistency`, `templatefile_sensitive_leak`, `remote_state_present`, `provider_alias_unused`, `provider_alias_module_mismatch`, `foreach_over_list`, `data_external_injection`, `tfstate_in_repo`, `submodule_version_missing`, `prod_no_deletion_protection`, `deprecated_datasource` | See in-source docstrings |
| `graph_check` | Cross-resource detector dispatched to a registered Python function. The catalogue YAML names the function via `function: <name>` and the dispatcher in `detect.py` routes to `_GRAPH_CHECKS[name]`. Use this for conditions that span ≥2 resources (e.g., a logging target's hardening, a Workload Identity binding's bidirectionality). To add a new graph check: implement the function in `detect.py` next to `_GRAPH_CHECKS`, register it in that dict, then reference `kind: graph_check, function: <name>` in the catalogue YAML. |

The detection pass walks every `.tf` file in scope, applies every catalogue
pattern, and produces `(file, line, finding_id)` triples. The judgement pass
then assigns urgency (starting from `default_urgency`, applying `escalation`
rules), collapses duplicates, and enriches with context.

## Sequencing within a run

Within a single run, the report assigns instance numbers per finding ID:
`SEC-GCP-IAM-001#1`, `SEC-GCP-IAM-001#2`, etc. Across runs the catalogue ID is the
stable join key — instance numbers are not.

## Adding a new entry

1. Pick the lowest unused `<NNN>` in the subdomain.
2. Write the YAML file. Validate the schema by running the self-test.
3. Add a fixture under `fixtures/<name>/` that triggers the new pattern.
4. Re-run the skill against the fixture and confirm the new ID surfaces.
5. Reference the new ID from any inline check list in `SKILL.md` that
   produces it (e.g., Step 2b → SEC-GCP-IAM-001).
