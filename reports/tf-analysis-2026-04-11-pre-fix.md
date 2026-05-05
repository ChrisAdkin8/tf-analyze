# tf-analyze Report — gcp-hashi-knowledge-base

**Date:** 2026-04-11
**Target:** `/Users/chris.adkin/Projects/gcp-hashi-knowledge-base/terraform`
**Mode:** `static`
**Focus:** `all`
**Catalogue version:** as of HEAD on `tf-analyze` main

---

## Scope summary

| Metric | Count |
|---|---|
| `.tf` files in scope | 32 |
| Modules | 4 (`hashicorp-docs-pipeline`, `terraform-graph-store`, `state-backend`, `bootstrap`) |
| Root scenarios | 1 (`terraform/`) |
| `.tfvars` files (non-example) | 0 (only `terraform.tfvars.example` checked in) |
| Detection-pass findings | 12 (10 unique after dedup of false positives) |
| Exploratory findings | 7 |
| Positive observations | 6 |

**Health score:** `100 − (15·0 + 7·0 + 3·5 + 1·6) = 79 / 100`

(0 CRITICAL, 0 HIGH, 5 MEDIUM, 6 LOW after triage)

---

## Step 0 — Pre-analysis (PASS)

| Check | Result |
|---|---|
| Credential patterns in `.tfvars` | PASS (no `.tfvars` files; only `terraform.tfvars.example` with placeholders) |
| Git history for `.tfvars` / `.tfstate` / `*.pem` adds | PASS (none) |
| `.tfstate` files on disk | PASS (none) |
| `.terraform.lock.hcl` exists | PASS (`terraform/.terraform.lock.hcl`) |
| `.terraform.lock.hcl` gitignored? | PASS (not in `.gitignore`; lock file is committable) |
| `terraform.tfvars` gitignored? | PASS (entry in `.gitignore`) |
| `corpus.auto.tfvars` gitignored? | PASS (entry in `.gitignore`) |
| Project docs loaded | `CLAUDE.md`, `Taskfile.yml` read; no `.tf-analyze-ignore.yaml` present |

**Intentional patterns extracted from CLAUDE.md** (used to suppress false positives):
- `google_vertex_ai_rag_corpus` is intentionally NOT managed in Terraform — workflow self-provisions it.
- `roles/iam.serviceAccountUser` self-grant on rag-pipeline-sa and graph-pipeline-sa is required for Cloud Build `actAs`.
- `oauth_token` (not `oidc_token`) on Cloud Scheduler → Workflows is required by `workflowexecutions.googleapis.com`.
- Spanner Graph DDL must be a single batch — cannot be split.
- Cloud Build substitutions must be `_`-prefixed.

**Note on auto-loaded CLAUDE.md mismatch:** the global memory references `aws-hashi-knowledge-base` (a sibling project). The CLAUDE.md actually used for analysis is the GCP project's own at `/Users/chris.adkin/Projects/gcp-hashi-knowledge-base/CLAUDE.md`.

---

## Findings

### MEDIUM (5)

#### `ROB-VALIDATION-001` — Module variables lack validation blocks
- `terraform/bootstrap/variables.tf:6` — `var.region`
- `terraform/modules/state-backend/variables.tf:6` — `var.region`
- `terraform/modules/hashicorp-docs-pipeline/variables.tf:6` — `var.region`
- `terraform/modules/hashicorp-docs-pipeline/variables.tf:46` — `var.environment`
- `terraform/modules/terraform-graph-store/variables.tf:6` — `var.region`
- `terraform/modules/terraform-graph-store/variables.tf:86` — `var.environment`

**Blast radius:** module
**Status:** TRUE POSITIVE (×6)

The root `terraform/variables.tf` already validates `region` (regex), `environment` (`contains([dev, staging, prod])`), `refresh_schedule`, `documentai_location`, etc. The same names are re-declared inside each child module without validation, so any caller bypassing the root (e.g., importing the module directly from another project, or `task bootstrap` for the bootstrap module) loses the guardrails.

**Recommendation (VERIFIED — pure HCL, no provider-side validation):**

```hcl
# in each child module
variable "region" {
  type        = string
  description = "..."
  default     = "us-central1"
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must look like 'us-central1' or 'europe-west2'."
  }
}

variable "environment" {
  type        = string
  description = "..."
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}
```

**Verification:** `terraform plan -var=region=garbage` should fail.

---

#### `ROB-LIFECYCLE-001` — Spanner instance missing `lifecycle.prevent_destroy`
- `terraform/modules/terraform-graph-store/spanner.tf:1` — `google_spanner_instance.graph`

**Blast radius:** single-resource (but holds entire graph state)
**Status:** TRUE POSITIVE

The instance has no `lifecycle { prevent_destroy = true }`. The child `google_spanner_database.graph` has `deletion_protection = var.spanner_database_deletion_protection` (defaults `true`), but **destroying the instance cascades to every database it holds**, bypassing the database-level guard. A `terraform destroy` would wipe the entire graph store.

**Recommendation (VERIFIED — pure HCL):**

```hcl
resource "google_spanner_instance" "graph" {
  # ... existing args ...

  lifecycle {
    prevent_destroy = true
  }
}
```

**Verification:** `terraform plan -destroy` should refuse with `Instance cannot be destroyed`.

**Escalation note:** the catalogue rule escalates to HIGH when monthly cost > $500 or production data is held. At 100 processing units (~$65/mo) and a dev-default `var.environment`, this stays MEDIUM.

---

#### `ROB-LIFECYCLE-001` — Spanner database missing `lifecycle.prevent_destroy` (mitigated)
- `terraform/modules/terraform-graph-store/spanner.tf:19` — `google_spanner_database.graph`

**Blast radius:** single-resource
**Status:** PARTIAL — `deletion_protection = var.spanner_database_deletion_protection` already provides API-level protection (defaults `true`). The catalogue rule checks for `lifecycle.prevent_destroy` specifically; since the resource attribute is the GCP-native equivalent, this is **defence-in-depth, not a critical gap**. Treat as MEDIUM only because removing `var.spanner_database_deletion_protection` from `terraform.tfvars` accidentally would re-enable destroy.

**Recommendation:** add `lifecycle { prevent_destroy = true }` for belt-and-braces, **or** mark `var.spanner_database_deletion_protection` `nullable = false` and remove the variable indirection.

---

#### `EXPLORATORY-AUDIT-001` — Cloud Audit Log coverage gap
- `terraform/audit.tf:11` — `local.audited_services`

**Blast radius:** infrastructure-wide
**Status:** EXPLORATORY (no catalogue ID — candidate for `SEC-LOGGING-002`)

`audit.tf` enables `DATA_READ` + `DATA_WRITE` audit logs for 4 services:

```hcl
audited_services = toset([
  "aiplatform.googleapis.com",
  "spanner.googleapis.com",
  "storage.googleapis.com",
  "cloudbuild.googleapis.com",
])
```

The pipeline also touches **`workflows.googleapis.com`**, **`cloudscheduler.googleapis.com`**, **`documentai.googleapis.com`**, **`iam.googleapis.com`**, and **`monitoring.googleapis.com`** (alert policies). Forensic reconstruction after a credential compromise is incomplete without those.

**Recommendation:**

```hcl
audited_services = toset([
  "aiplatform.googleapis.com",
  "spanner.googleapis.com",
  "storage.googleapis.com",
  "cloudbuild.googleapis.com",
  "workflows.googleapis.com",
  "cloudscheduler.googleapis.com",
  "documentai.googleapis.com",
  "iam.googleapis.com",
])
```

**Verification:** `gcloud logging read 'protoPayload.serviceName="workflows.googleapis.com"' --limit=1` should return at least one entry after the next pipeline run.

---

#### `EXPLORATORY-MONITORING-001` — Alerting silently disabled when `notification_email` is empty
- `terraform/modules/hashicorp-docs-pipeline/monitoring.tf:2` (count guard)
- `terraform/variables.tf:87` (default `""`)

**Blast radius:** environment
**Status:** EXPLORATORY

Both `google_monitoring_alert_policy` resources use `count = var.notification_email != "" ? 1 : 0`. The variable defaults to `""`, so a `task up` with default vars deploys the pipeline **with zero alerting**. There is no warning, no log line, no plan diff that flags this.

The CLAUDE.md says "Optional - set to receive email alerts on failures", which makes the silent disable **documented**, but the failure mode (production deploy with no alerts) is exactly the kind of pain ROB findings exist to prevent.

**Recommendation (one of):**
1. Make `notification_email` required with a validation rule that allows the literal string `"none"` to opt out:
   ```hcl
   variable "notification_email" {
     type = string
     validation {
       condition     = var.notification_email == "none" || can(regex("@", var.notification_email))
       error_message = "notification_email must be a valid email or the literal 'none' to acknowledge no alerting."
     }
   }
   ```
2. Or emit a Pub/Sub notification channel as a no-op fallback so the alert policies always exist; route Pub/Sub to a dead-letter for dev.

---

### LOW (6)

#### `ROB-VERSION-001` — `required_version = ">= 1.5"` floor predates skill assumptions
- `terraform/versions.tf:2`
- `terraform/bootstrap/versions.tf:7`

**Status:** TRUE POSITIVE (catalogue regex matches `1.[0-5]`); MILD severity in practice — both files include an explicit upper bound `< 2.0`, which is the more important half. The skill catalogue assumes 1.6+ for `*.tftest.hcl`, `import` blocks, and `optional()` in object types; if you don't use those, this stays cosmetic.

**Recommendation:** bump to `required_version = "~> 1.10"` once CI agrees.

**Verification:** `terraform version` must satisfy the new constraint.

---

#### `EXPLORATORY-DRY-001` — Bucket-name hash pattern repeated 3× across modules
- `terraform/modules/state-backend/main.tf:11` — `${var.project_id}-tf-state-${substr(sha256(var.project_id), 0, 8)}`
- `terraform/modules/hashicorp-docs-pipeline/locals.tf:2` — `${var.project_id}-rag-docs-${substr(...)}`
- `terraform/modules/terraform-graph-store/locals.tf:2` — `${var.project_id}-graph-staging-${substr(...)}`

**Blast radius:** infrastructure-wide
**Status:** EXPLORATORY

The 8-char hash naming pattern is duplicated. Not a bug — each module is correctly self-contained. Worth noting only because adding a fourth bucket means a fourth copy. A `bucket_name(prefix, project_id)` local helper would normalise this, but the 1-line idiom is readable and the indirection cost is real. **Not worth fixing unless a fourth bucket arrives.**

---

#### `EXPLORATORY-LIFECYCLE-001` — Bucket lifecycle rules don't reap noncurrent versions
- `terraform/modules/hashicorp-docs-pipeline/storage.tf:15` — `rag_docs` bucket, `age=90` Delete
- `terraform/modules/terraform-graph-store/storage.tf:15` — `graph_staging` bucket, `age=30` Delete

**Blast radius:** single-resource
**Status:** EXPLORATORY

Both buckets enable `versioning { enabled = true }` but their `lifecycle_rule` blocks lack `condition { with_state = "ARCHIVED" }` or `num_newer_versions`. With versioning on, a `Delete` action on a live object creates a delete marker — the noncurrent version persists indefinitely, accumulating cost. For a weekly-refresh pipeline, this is small (~52 noncurrent objects/year × small file count) but unbounded.

**Recommendation:**

```hcl
lifecycle_rule {
  condition {
    age        = 90
    with_state = "LIVE"
  }
  action { type = "Delete" }
}

lifecycle_rule {
  condition {
    days_since_noncurrent_time = 30
    with_state                 = "ARCHIVED"
  }
  action { type = "Delete" }
}
```

**Verification:** `gsutil ls -a gs://<bucket>/**` after 30 days should show no noncurrent objects.

---

#### `EXPLORATORY-VARS-001` — `bootstrap/variables.tf` and root `variables.tf` redeclare without sharing
- `terraform/bootstrap/variables.tf:1-17`

**Blast radius:** module
**Status:** EXPLORATORY

The bootstrap module declares `project_id`, `region`, `kms_key_name` independently. Bootstrap is intentionally a separate Terraform configuration (different state), so a shared variables file is awkward — but `region` is currently inconsistent with the root's validation regex. Acceptable trade-off but worth a comment.

---

#### `EXPLORATORY-LOCKFILE-001` — `.terraform.lock.hcl` is on disk but not tracked in git
- `terraform/.terraform.lock.hcl`

**Status:** EXPLORATORY — `git ls-files terraform/.terraform.lock.hcl` returned empty. The lock file is **not committed**, and it's also **not in `.gitignore`**, so it's just untracked. CI runs without a committed lock file may pull a different provider patch version than dev.

**Recommendation:** `git add terraform/.terraform.lock.hcl && git commit -m "Pin provider versions"`. Catalogue ID candidate: `SUP-LOCK-001`.

---

#### `EXPLORATORY-AUDIT-002` — `google_project_iam_audit_config` for-each over a literal toset
- `terraform/audit.tf:21`

**Status:** INFO/LOW. Stylistic — `local.audited_services` is built once from a literal `toset([...])`. This is exactly the pattern the catalogue treats as best practice (one resource per service, idempotent). No action needed, just want to flag that the comment "One resource per service - the API rejects multiple audit_config blocks for the same service in a single resource" is a load-bearing constraint and should not be refactored away.

---

### Suppressed Findings

#### `SEC-PROVIDER-001` — FALSE POSITIVE (×2)
- `terraform/versions.tf:2`
- `terraform/bootstrap/versions.tf:7`

The catalogue regex `version\s*=\s*">=\s*[0-9]` matches the `terraform { required_version = ">= 1.5, < 2.0" }` line because `required_version` ends with `version`. The actual provider blocks below use `version = "~> 6.50"` and `version = "~> 6.0"` — both are properly upper-bounded with the pessimistic operator.

**Action:** suppress in this report. **Catalogue follow-up:** anchor the regex with a leading word boundary, e.g. `(?<![_a-zA-Z])version\s*=\s*">=\s*[0-9]`. File a fix against `catalog/SEC-PROVIDER-001.yaml`.

---

## Positive observations

1. **Exemplary IAM scoping with documented rationale** — `terraform/modules/hashicorp-docs-pipeline/locals.tf:21-45` explains why every project-level role *cannot* be scoped further (RAG corpus has no IAM resource type, Cloud Build has no per-trigger IAM, Workflows IAM resource doesn't exist in the provider). This is exactly what Step 2b asks for.

2. **Bucket-scoped IAM replacing project-level** — both pipelines use `google_storage_bucket_iam_member` for `roles/storage.objectAdmin` instead of granting it project-wide. `terraform/modules/hashicorp-docs-pipeline/iam.tf:20-24`, `terraform/modules/terraform-graph-store/iam.tf:29-33`.

3. **Spanner database scoped IAM** — `google_spanner_database_iam_member` at `terraform/modules/terraform-graph-store/iam.tf:19-25` instead of `roles/spanner.databaseUser` at project scope.

4. **Cloud Audit Logs configured** — `terraform/audit.tf` enables DATA_READ + DATA_WRITE for 4 services. Many GCP repos have *zero* explicit audit config; this is above baseline (the gap is coverage, not absence).

5. **GCS state bucket hardened** — `uniform_bucket_level_access = true`, `public_access_prevention = "enforced"`, `versioning { enabled = true }`, `lifecycle { prevent_destroy = true }`, optional CMEK. `terraform/modules/state-backend/main.tf:14-36`.

6. **Workflows have `deletion_protection = true`** — both `google_workflows_workflow` resources guard against accidental destroy. `terraform/modules/hashicorp-docs-pipeline/workflow.tf:7`, `terraform/modules/terraform-graph-store/workflow.tf:7`.

---

## Action plan (priority order)

| # | ID | File | Action | Effort |
|---|---|---|---|---|
| 1 | `ROB-LIFECYCLE-001` | `terraform/modules/terraform-graph-store/spanner.tf:1` | Add `lifecycle { prevent_destroy = true }` to `google_spanner_instance.graph` | 2 lines |
| 2 | `EXPLORATORY-AUDIT-001` | `terraform/audit.tf:11` | Extend `local.audited_services` to include workflows, cloudscheduler, documentai, iam | 4 lines |
| 3 | `EXPLORATORY-MONITORING-001` | `terraform/variables.tf:87` | Validate `notification_email` or require an explicit `"none"` opt-out | ~6 lines |
| 4 | `ROB-VALIDATION-001` (×6) | `terraform/{bootstrap,modules/*}/variables.tf` | Copy `region` and `environment` validation blocks from root into each child | ~12 lines/module |
| 5 | `EXPLORATORY-LOCKFILE-001` | `terraform/.terraform.lock.hcl` | `git add` and commit the lock file | git command |
| 6 | `EXPLORATORY-LIFECYCLE-001` | `storage.tf` (both modules) | Add second `lifecycle_rule` to reap noncurrent versions | ~8 lines |
| 7 | `ROB-VERSION-001` | `versions.tf` (both) | Bump floor to `~> 1.10` after CI confirms | 1 line |
| 8 | (catalogue fix) | `catalog/SEC-PROVIDER-001.yaml` | Anchor regex to fix `required_version` false-positive | 1 char |

---

## Step 14 — Recommendation verification

| Recommendation | Verification path | Status |
|---|---|---|
| Spanner instance `lifecycle { prevent_destroy = true }` | Pure HCL, terraform-core feature | **VERIFIED** |
| Variable `validation { ... }` blocks | Pure HCL, terraform 0.13+ | **VERIFIED** |
| Audit-config service additions | All 4 added services exist (`workflows.googleapis.com`, `cloudscheduler.googleapis.com`, `documentai.googleapis.com`, `iam.googleapis.com`); audit log types `DATA_READ`/`DATA_WRITE` apply uniformly | **VERIFIED** |
| Bucket lifecycle `with_state = "LIVE"` / `days_since_noncurrent_time` | Both attributes exist in `google_storage_bucket.lifecycle_rule.condition` since google provider 4.x | **VERIFIED** |
| `notification_email` validation block | Pure HCL | **VERIFIED** |
| `terraform required_version = "~> 1.10"` | Pure HCL, requires Terraform 1.10+ to be installed locally | **NEEDS-REVIEW** (depends on local TF version) |

No `NEEDS-RECONSIDERATION` or `SPECULATIVE` recommendations in this report.

---

## Delta from prior report

No prior `tf-analysis-*.md` exists in `reports/`. This is the baseline.

---

## Catalogue follow-ups (file as separate work)

1. **`SEC-PROVIDER-001` regex anchoring** — false positive on `required_version` (see Suppressed Findings). One-character fix.
2. **New catalogue entry: `SUP-LOCK-001`** — `.terraform.lock.hcl` exists but is untracked. Currently surfaced only as exploratory.
3. **New catalogue entry: `SEC-LOGGING-002`** — Cloud Audit Log coverage gap (audited_services subset of services-in-use). Distinct from `SEC-LOGGING-001` which checks for total absence.
4. **New catalogue entry: `OPS-ALERT-001`** — alert policies gated on optional notification channel default to silent. Real production hazard.
5. **New catalogue entry: `STK-BUCKET-002`** — versioning enabled but lifecycle_rule lacks noncurrent reap. Companion to `STK-BUCKET-001` (versioning missing).
