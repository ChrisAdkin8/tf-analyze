# OWASP A08:2021 — Software and Data Integrity Failures
# Cloud: GCP
#
# Three integrity failures common in GCP Terraform:
#
#   1. GCS buckets without object versioning. An accidental
#      `gsutil rm` or `terraform destroy` is unrecoverable. State
#      buckets and audit-log buckets are the most painful instances.
#   2. Stale `moved` blocks — Terraform 1.5+ feature for safe
#      refactoring. Once apply runs and state reflects the new
#      address, the block should be deleted; leaving it accumulates
#      noise and confuses future readers.
#   3. Stale `removed` blocks — Terraform 1.7+ feature for declarative
#      destroy/forget. Same issue: once applied, delete the block.
#
# Real-world impact:
#   - State bucket without versioning + a single botched apply =
#     the entire infrastructure is permanently un-managed.
#   - 80-line moved-block trail in a 200-line module reads as
#     "active refactor in progress" to a new reader, but is actually
#     dead history.
#
# Expected tf-analyze findings:
#   - STK-GCP-BUCKET-001    MEDIUM   GCS bucket missing versioning
#   - ROB-MOVED-001     LOW      Stale moved block may need cleanup
#   - ROB-REMOVED-001   LOW      Stale removed block may need cleanup
#
# Fix summary: turn on versioning + a lifecycle_rule expiring
# non-current versions; delete moved/removed blocks immediately
# after the apply that consumed them.

resource "google_storage_bucket" "no_versioning" {
  name                        = "demo-no-versioning"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  # versioning {} block intentionally omitted

  lifecycle {
    prevent_destroy = true
  }
}

# Stale moved block — refactor was applied months ago.
moved {
  from = google_storage_bucket.old_legacy
  to   = google_storage_bucket.no_versioning
}

# Stale removed block — destroy was applied last quarter.
removed {
  from = google_storage_bucket.deprecated_audit
  lifecycle {
    destroy = true
  }
}
