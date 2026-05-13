# Auto-generated clean fixture for STK-GCP-STORAGE-RETENTION-001.
# GCS bucket missing retention_policy (ransomware/regulatory risk)
# This is a CORRECT configuration; STK-GCP-STORAGE-RETENTION-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket" "example" {
  name                        = "audit-logs"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  retention_policy {
    retention_period = 7776000
    is_locked        = false
  }
}
