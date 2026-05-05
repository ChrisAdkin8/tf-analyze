# Terraform Code Analysis Report

**Date:** 2026-04-11 (post-fix re-run)
**Scope:** `/Users/chris.adkin/Projects/gcp-hashi-knowledge-base/terraform`
**Files scanned:** 33 `.tf` files across 4 modules + 1 root scenario
**Focus:** all
**Mode:** static
**Health Grade:** **B (88 / 100)** — up from B (79) in `tf-analysis-2026-04-11-pre-fix.md`

---

## Executive Summary

The codebase improved meaningfully between runs: 8 of the prior report's findings have been fully resolved, including all 6 `ROB-VALIDATION-001` instances (module variable validation), the audit-log coverage gap, and the silent-alerting hazard. What remains is a small, well-understood tail: two intentionally-deferred `ROB-LIFECYCLE-001` findings on Spanner, two `ROB-VERSION-001` LOWs that depend on a Terraform CLI version bump, and a handful of LOW exploratory items. No CRITICAL or HIGH findings remain.

**Strengths:** module variables now carry validation parity with the root; Cloud Audit Logs cover all 8 services the pipeline touches (workflows, scheduler, IAM, documentai included); `notification_email` requires an explicit `"none"` opt-out so silent alert disables are no longer possible; all GCS buckets retain `prevent_destroy` + `uniform_bucket_level_access` + `public_access_prevention`; IAM scoping is documented per-role in `locals.tf`.

**Finding counts by urgency:**

| Urgency | Count |
|---------|-------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 2 |
| LOW | 6 |
| INFO | 6 (positive observations) |

### Delta (vs `tf-analysis-2026-04-11-pre-fix.md`)

| Status | Count | Findings |
|---|---|---|
| **Resolved** | 8 | `ROB-VALIDATION-001#1` … `#6`, `EXPLORATORY-AUDIT-001`, `EXPLORATORY-MONITORING-001` |
| **New** | 0 | — |
| **Unchanged (intentional)** | 2 | `ROB-LIFECYCLE-001#1` (Spanner instance), `ROB-LIFECYCLE-001#2` (Spanner database) |
| **Unchanged (LOW)** | 6 | `ROB-VERSION-001#1`, `#2`, `EXPLORATORY-DRY-001`, `EXPLORATORY-LIFECYCLE-001`, `EXPLORATORY-VARS-001`, `EXPLORATORY-LOCKFILE-001`, `EXPLORATORY-AUDIT-002` |
| **Suppressed (false positive)** | 2 | `SEC-PROVIDER-001#1`, `#2` |

### Finding density by file

| File | Lines | CRIT | HIGH | MED | LOW | Total | Density |
|---|---|---|---|---|---|---|---|
| `terraform/modules/terraform-graph-store/spanner.tf` | 35 | 0 | 0 | 2 | 0 | 2 | 5.7 |
| `terraform/versions.tf` | 19 | 0 | 0 | 0 | 1 | 1 | 5.3 |
| `terraform/bootstrap/versions.tf` | 14 | 0 | 0 | 0 | 1 | 1 | 7.1 |

All other files have zero active findings.

---

## 1. Security Posture

_No findings — section omitted._

(SEC-PROVIDER-001 ×2 detections are false positives; see Section 11.)

---

## 2. DRY and Code Reuse

### LOW

- **[EXPLORATORY-DRY-001] Bucket-name hash pattern repeated 3×** — `terraform/modules/state-backend/main.tf:11`, `terraform/modules/hashicorp-docs-pipeline/locals.tf:2`, `terraform/modules/terraform-graph-store/locals.tf:2` | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW
  Description: The 8-char SHA hash naming idiom `${var.project_id}-X-${substr(sha256(var.project_id), 0, 8)}` is duplicated in 3 modules. Each module is correctly self-contained, so this is not a bug — only a refactor opportunity if a fourth bucket arrives.
  Recommendation: Leave as-is. Adding a shared helper module just to remove a 1-line idiom would add more indirection than it removes. Revisit if a fourth bucket joins the layout.
  Verification: n/a (intentionally a no-op).

---

## 3. Style and Conventions

_No findings — section omitted._ (`terraform fmt -check -recursive` is clean.)

---

## 4. Robustness

### MEDIUM

- **[ROB-LIFECYCLE-001#1] Spanner instance missing `lifecycle.prevent_destroy`** — `terraform/modules/terraform-graph-store/spanner.tf:1` | Blast: single-resource (cascades to all child databases) | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `google_spanner_instance.graph` has no `lifecycle { prevent_destroy = true }` block. The child `google_spanner_database.graph` has `deletion_protection = var.spanner_database_deletion_protection` (defaults `true`), but **destroying the instance cascades to every database it holds**, bypassing the database-level guard. This finding was acknowledged in the prior report and intentionally not addressed in this fix cycle.
  Recommendation:
  ```hcl
  resource "google_spanner_instance" "graph" {
    # ... existing args ...
    lifecycle {
      prevent_destroy = true
    }
  }
  ```
  Verification: `terraform plan -destroy` should refuse with `Instance cannot be destroyed`.

- **[ROB-LIFECYCLE-001#2] Spanner database missing `lifecycle.prevent_destroy`** — `terraform/modules/terraform-graph-store/spanner.tf:18` | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED (but mitigated)
  Description: `google_spanner_database.graph` lacks `lifecycle { prevent_destroy = true }`. The catalogue rule fires by structural pattern, but the resource argument `deletion_protection = var.spanner_database_deletion_protection` (default `true`) provides equivalent API-level protection. Treat as defence-in-depth, not a critical gap. Intentionally deferred.
  Recommendation: Add `lifecycle { prevent_destroy = true }` for belt-and-braces, OR set `nullable = false` on `var.spanner_database_deletion_protection` to prevent accidental override.
  Verification: `terraform plan -destroy` should refuse.

### LOW

- **[ROB-VERSION-001#1] `required_version` floor below skill assumptions** — `terraform/versions.tf:2` | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW
  Description: `required_version = ">= 1.5, < 2.0"`. The lower bound `1.5` is below the recommended `1.6+` floor for `*.tftest.hcl`, `import` blocks, and `optional()` in object types. The upper bound is correctly set.
  Recommendation: `required_version = "~> 1.10"` once CI confirms the runners have a sufficient version.
  Verification: `terraform version` must satisfy the constraint after the bump.

- **[ROB-VERSION-001#2] `required_version` floor below skill assumptions** — `terraform/bootstrap/versions.tf:7` | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: NEEDS-REVIEW
  Description: Same constraint string as `#1`, same remediation.
  Recommendation: Bump to `~> 1.10`.
  Verification: Same as `#1`.

- **[EXPLORATORY-LIFECYCLE-001] Bucket lifecycle rules don't reap noncurrent versions** — `terraform/modules/hashicorp-docs-pipeline/storage.tf:15` (rag_docs, age=90), `terraform/modules/terraform-graph-store/storage.tf:15` (graph_staging, age=30) | Blast: single-resource | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: Both buckets enable `versioning { enabled = true }` but their `lifecycle_rule` blocks lack `with_state = "ARCHIVED"` or `num_newer_versions`. Noncurrent versions persist indefinitely, accumulating cost. Small impact for a weekly pipeline but unbounded.
  Recommendation:
  ```hcl
  lifecycle_rule {
    condition  { age = 90  with_state = "LIVE" }
    action     { type = "Delete" }
  }
  lifecycle_rule {
    condition  { days_since_noncurrent_time = 30  with_state = "ARCHIVED" }
    action     { type = "Delete" }
  }
  ```
  Verification: `gsutil ls -a gs://<bucket>/**` after 30 days should show no noncurrent objects.

- **[EXPLORATORY-VARS-001] Bootstrap and root variable definitions overlap without sharing** — `terraform/bootstrap/variables.tf:1-21` | Blast: module | CIS: n/a | Effort: Medium | Status: NEEDS-REVIEW
  Description: Bootstrap re-declares `project_id` and `region`. Bootstrap is intentionally a separate Terraform configuration (different state file), so a shared variables file is awkward. After the latest fix, both files now apply identical region validation, so the divergence is cosmetic.
  Recommendation: No action. Document the intentional duplication if it becomes a maintenance hazard.
  Verification: n/a.

- **[EXPLORATORY-LOCKFILE-001] `.terraform.lock.hcl` exists on disk but is not tracked in git** — `terraform/.terraform.lock.hcl` | Blast: infrastructure-wide | CIS: n/a | Effort: Small | Status: VERIFIED
  Description: `git ls-files terraform/.terraform.lock.hcl` returns empty. The lock file is neither committed nor in `.gitignore` — just untracked. CI runs without a committed lock file may pull a different provider patch version than dev workstations.
  Recommendation: `git add terraform/.terraform.lock.hcl && git commit -m "Pin provider versions"`. Catalogue ID candidate: `SUP-LOCK-001`.
  Verification: `git ls-files terraform/.terraform.lock.hcl` should print the path.

- **[EXPLORATORY-AUDIT-002] `audit.tf` for-each pattern is intentionally one-resource-per-service** — `terraform/audit.tf:21` | Blast: infrastructure-wide | CIS: 2.1 | Effort: n/a | Status: NEEDS-REVIEW
  Description: Style note flagged in the prior report. The comment "the API rejects multiple audit_config blocks for the same service in a single resource" is a load-bearing constraint and should not be refactored away.
  Recommendation: No action. Preserved as INFO-level documentation.
  Verification: n/a.

---

## 5. Simplicity

_No findings — section omitted._

---

## 6. Operational Readiness

_No findings — section omitted._ (Both monitoring alert policies are now enforceable via the `notification_email` validation gate.)

---

## 7. CI/CD and Testing Maturity

_No new findings in this re-run. Taskfile-driven CI was assessed in the prior report and remains adequate (`task ci` runs `fmt:check + validate + shellcheck + tests`)._

---

## 8. Cross-Module Contracts

_No findings — section omitted._

---

## 9. Stack-Specific Findings

_No findings — section omitted._

---

## 10. CLAUDE.md Compliance

All five intentional patterns documented in `gcp-hashi-knowledge-base/CLAUDE.md` continue to be honored:
- `google_vertex_ai_rag_corpus` is intentionally not managed in Terraform — confirmed absent.
- `roles/iam.serviceAccountUser` self-grant on rag-pipeline-sa and graph-pipeline-sa — present in `iam.tf` of both modules.
- `oauth_token` (not `oidc_token`) on Cloud Scheduler → Workflows — present in both schedulers.
- Spanner Graph DDL is a single batch — confirmed in `terraform-graph-store/locals.tf:36-69`.
- Cloud Build substitutions `_`-prefixed — confirmed in `monitoring.tf:56`.

---

## 11. Suppressed Findings

- **[SEC-PROVIDER-001#1] FALSE POSITIVE** — `terraform/versions.tf:2`
- **[SEC-PROVIDER-001#2] FALSE POSITIVE** — `terraform/bootstrap/versions.tf:7`

  The catalogue regex `version\s*=\s*">=\s*[0-9]` matches the suffix `version` of `required_version` in `terraform { required_version = ">= 1.5, < 2.0" }`. Both files use `~> 6.50` / `~> 6.0` for the actual provider blocks, which are correctly upper-bounded. **Catalogue follow-up:** anchor regex with `(?<![_a-zA-Z])`. These count at zero weight in the health score because they are false positives, not accepted risks.

---

## 12. Positive Findings

1. **Module variable validation parity achieved (NEW)** — Region and environment validation blocks were copied from `terraform/variables.tf` into all four child modules in this fix cycle. Direct module imports from a sibling project now hit the same guardrails as the root.

2. **Audit-log coverage extended to 8 services (NEW)** — `terraform/audit.tf:11` now includes `workflows.googleapis.com`, `cloudscheduler.googleapis.com`, `documentai.googleapis.com`, and `iam.googleapis.com` alongside the original 4. Forensic reconstruction after a credential compromise is now complete for the entire pipeline footprint.

3. **`notification_email` requires explicit opt-out (NEW)** — Default changed from `""` to `"none"`, with a validation block that rejects any other empty/garbage value. The silent-disable failure mode (`task up` shipping with no alerting) is no longer possible. `terraform/variables.tf:87`, `terraform/modules/hashicorp-docs-pipeline/variables.tf:35`, `terraform/modules/hashicorp-docs-pipeline/monitoring.tf:2,14`.

4. **Exemplary IAM scoping with documented rationale** — `terraform/modules/hashicorp-docs-pipeline/locals.tf:21-45` explains *why* every project-level role cannot be scoped further (Workflows IAM resource doesn't exist in the provider, Cloud Build has no per-trigger IAM, RAG corpus has no IAM resource type).

5. **Bucket-scoped + database-scoped IAM** — `google_storage_bucket_iam_member` and `google_spanner_database_iam_member` replace the project-level equivalents wherever the API allows.

6. **Stateful resources protected** — All 3 GCS buckets carry `lifecycle { prevent_destroy = true }`; both Cloud Workflows have `deletion_protection = true`; the state-backend bucket adds `uniform_bucket_level_access`, `public_access_prevention = enforced`, versioning, and optional CMEK.

---

## 13. Recommended Action Plan

| Priority | Finding | Section | Effort | Blast Radius | Description |
|---|---|---|---|---|---|
| 1 | `ROB-LIFECYCLE-001#1` | Robustness | Small | single-resource (cascade) | Add `lifecycle { prevent_destroy = true }` to `google_spanner_instance.graph`. Highest priority because instance destroy cascades to all child databases. |
| 2 | `EXPLORATORY-LOCKFILE-001` | Robustness | Small | infrastructure-wide | `git add terraform/.terraform.lock.hcl` and commit — closes the dev/CI provider drift gap. |
| 3 | `ROB-LIFECYCLE-001#2` | Robustness | Small | single-resource | Belt-and-braces `lifecycle { prevent_destroy = true }` on Spanner database, or `nullable = false` on the toggle variable. |
| 4 | `EXPLORATORY-LIFECYCLE-001` | Robustness | Small | single-resource | Add a second `lifecycle_rule` to both buckets to reap noncurrent versions. |
| 5 | `ROB-VERSION-001#1`, `#2` | Robustness | Small | infrastructure-wide | Bump `required_version` floor from `1.5` to `~> 1.10` after CI confirms its runner version. |
| 6 | (catalogue fix) | Skill | Small | n/a | Anchor `SEC-PROVIDER-001` regex to fix the `required_version` false positive. File against `catalog/SEC-PROVIDER-001.yaml`. |

### Related findings

- `ROB-LIFECYCLE-001#1` + `ROB-LIFECYCLE-001#2` → fix together; the instance-level `prevent_destroy` is the load-bearing one.
- `EXPLORATORY-LOCKFILE-001` + `ROB-VERSION-001` → both relate to provider/Terraform-version reproducibility. Doing them in the same PR keeps the version-pinning story coherent.

---

## Catalogue follow-ups (filed against the skill itself)

1. **`SEC-PROVIDER-001` regex anchoring** — false positive on `required_version`. One-character fix (`(?<![_a-zA-Z])` lookbehind).
2. **New stub: `SUP-LOCK-001`** — `.terraform.lock.hcl` exists but is untracked.
3. **New stub: `SEC-LOGGING-002`** — Cloud Audit Log coverage gap (audited_services subset of services-in-use).
4. **New stub: `OPS-ALERT-001`** — alert policies gated on optional notification channel default to silent.
5. **New stub: `STK-BUCKET-002`** — versioning enabled but lifecycle_rule lacks noncurrent reap.
