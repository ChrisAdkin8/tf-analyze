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
section: security            # required, one of: security|robustness|dry|style|simplicity|ops|cicd|module|module-reuse|stack|verification
default_urgency: HIGH        # required, one of: CRITICAL|HIGH|MEDIUM|LOW|INFO
blast_radius: module         # required, one of: single-resource|module|environment|infrastructure-wide
status: active               # optional, default active. one of: active|deprecated|experimental
cis:                         # optional, list of CIS GCP v4.0 control IDs
  - "1.6"
mitre:                       # optional, ATT&CK technique IDs (Tnnnn or Tnnnn.nnn)
  - "T1078.004"              # see scripts/detect.py:MITRE_ATTACK_VERSION for the pin
cwe:                         # optional, CWE IDs in canonical "CWE-<digits>" form
  - "CWE-269"                # cwe.mitre.org/data/definitions/269.html
  - "CWE-732"
d3fend:                      # optional, MITRE D3FEND defensive-technique IDs
  - "D3-PA"                  # Privileged Account Management
  - "D3-MFA"                 # Multi-factor Authentication
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
applies_when:                # optional, gate the rule on provider/Terraform version
  min_provider:              # rule fires only when required_providers allows the listed minimum
    aws: "5.0"
  min_terraform: "1.10"      # rule fires only when terraform.required_version allows ≥ 1.10
```

### `applies_when` semantics

Use `applies_when` when the catalogue argument the rule checks **does not exist** on older providers (or older Terraform versions). Behaviour is permissive by design:

- An empty / missing constraint always passes — rules without `applies_when` always run.
- An unparseable constraint clause is skipped (the rule still runs).
- The minimum-provider check uses `_provider_constraint_allows`, which accepts every Terraform constraint clause shape (`>=`, `<=`, `<`, `>`, `~>`, `=`, `!=`, comma-separated combinations).
- Skipped rules are reported on stderr as `# N rule(s) skipped due to applies_when …` so users know rules are conditionally off rather than silently disabled.

Adopt `applies_when` only when the gate is **substantive** — i.e., the rule would emit false positives on older providers because the argument it checks doesn't exist there. Don't add it just because the argument is "newer-ish"; permissive defaults are better than over-gated ones.

### Threat-language taxonomies — `mitre`, `cwe`, `d3fend`

Three optional fields tag a rule with adversary / weakness / defense ontologies. All three flow into SARIF (as flat tags), into the per-rule docs page (as bulleted reference blocks), and — in the `mitre` case — into `--format mitre` tactic-grouped output.

| Field | Form | Validation | Curation principle |
|---|---|---|---|
| `mitre` | `["Tnnnn"]` or `["Tnnnn.nnn"]` (sub-techniques preferred) | Pinned against `MITRE_ATTACK_VERSION` (currently v17 / April 2025); validated by [`_MITRE_TECHNIQUE_INFO`](../scripts/detect.py) at engine load | Map only when the link is unambiguous; vague mappings hurt the SOC-readability of `--format mitre` |
| `cwe` | `["CWE-<digits>"]` (e.g. `CWE-732`) | Regex-validated by `validate_catalog_entry`; SARIF taxonomies emit verbatim | Map the obvious weakness type — usually one or two CWE IDs per rule; more is noise |
| `d3fend` | `["D3-<TOKEN>"]` (e.g. `D3-MFA`) | Regex-validated by `validate_catalog_entry`; SARIF tags emit `d3fend:D3-<TOKEN>` | Derived from the rule's `mitre:` via D3FEND's [ATT&CK ↔ D3FEND ontology](https://d3fend.mitre.org/); curated subset only |

Bulk-assign all three via [`scripts/apply_mitre.py`](../scripts/apply_mitre.py) — the in-script manifests are the single source of truth for the catalogue's coverage; re-running is idempotent.

Common D3FEND IDs the catalogue uses today (full list in `apply_mitre.py`):

| ID | Defensive technique | Typical `mitre:` partner |
|---|---|---|
| `D3-MFA` | Multi-factor Authentication | `T1078.004` (Valid Accounts: Cloud) |
| `D3-PA` | Privileged Account Management | `T1078.004`, `T1098.001` |
| `D3-CH` | Credential Hardening | `T1552.001`, `T1098.001` |
| `D3-EAR` | Encrypted Sensitive Data (at rest) | `T1530` |
| `D3-EI` | Encrypted Information / In Transit | `T1071.001`, `T1040` |
| `D3-IAA` | Inbound Application Allow-listing | `T1190`, `T1133` |
| `D3-FAA` | File Access Auditing | `T1562.008` |
| `D3-NTA` | Network Traffic Analysis | `T1190`, `T1562.008` |
| `D3-SCA` | Software Component Analysis | `T1195.002` |
| `D3-AL` | Account Locking | `T1110.001`, `T1078` |
| `D3-PSH` | Process Self-Modification (shielded boot) | `T1542.003` |

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
| `foreach_keyset_unstable` | A `for_each` whose keyset is derived from another managed resource's attribute (splat `aws_subnet.x[*].id` or comprehension `[for s in aws_subnet.x : s.id]`). Re-keys on every upstream resource-set change → destroy/create on every existing instance. Leading identifier is checked against a deny-list of safe scopes (`var`, `local`, `data`, `module`, `each`, `count`) so input-driven keysets don't fire. |
| `module_unused` | A directory that declares `variable {}` and/or `output {}` blocks but is not referenced by any `module { source = "<relpath>" }` block in the scan corpus. Conservative — only fires on directories with both an input/output contract and zero referrers. |
| `graph_check` | Cross-resource detector dispatched to a registered Python function. The catalogue YAML names the function via `function: <name>` and the dispatcher in `detect.py` routes to `_GRAPH_CHECKS[name]`. Use this for conditions that span ≥2 resources (e.g., a logging target's hardening, a Workload Identity binding's bidirectionality). To add a new graph check: implement the function in `detect.py` next to `_GRAPH_CHECKS`, register it in that dict, then reference `kind: graph_check, function: <name>` in the catalogue YAML. |
| `registry_fingerprint` | Module-reuse detector. Matches every directory's resource cluster against a fingerprint declared on the entry's top-level `fingerprint:` block (required types + supporting types + threshold + exclusions). One positive match per directory becomes one INFO-tier finding pointing at the registry module that the cluster resembles. Generic — no per-rule Python; add a new community-module rule by writing the YAML alone. See `MOD-REUSE-AWS-VPC-001.yaml` for a worked example. |

### `registry_fingerprint` schema

A rule using `kind: registry_fingerprint` adds a top-level `fingerprint:` block (separate from `patterns:`). All fields are validated by `validate_catalog_entry`:

```yaml
patterns:
  - kind: registry_fingerprint
    fingerprint: aws_vpc_module          # informational; the matcher reads from `fingerprint:` below
    description: "What this fingerprint detects."

fingerprint:
  registry_module: "<namespace>/<module>/<provider>"   # e.g. terraform-aws-modules/vpc/aws
  registry_url:    "<https://registry.terraform.io/modules/...>"
  min_version:     "~> 5.0"                            # for the recommendation snippet only
  required:                                            # all must meet their min count
    - type: aws_vpc
      min: 1
    - type: aws_subnet
      min: 2
  supporting:                                          # need ≥ threshold of these types
    threshold: 3
    types:
      - aws_internet_gateway
      - aws_nat_gateway
      - aws_route_table
      - ...
  exclusions:                                          # signals that bespoke is intentional
    - aws_vpc_ipam_pool
```

Findings emitted by the matcher carry two extra fields beyond the standard finding shape:
- `confidence` — `low` / `medium` / `high`. Scales with how far the cluster overshoots the supporting-types threshold.
- `registry_url` — verbatim from the catalogue entry, used by the VS Code Module Reuse Advisor panel and the per-rule docs page.

Module-reuse rules MUST default to `default_urgency: INFO` and `section: module-reuse`. INFO carries weight 0 in the score formula, so these findings never gate CI by default.

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
