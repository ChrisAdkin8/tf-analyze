# Expected findings:
#  - STK-GCP-STORAGE-RETENTION-001 MEDIUM — no retention_policy

resource "google_storage_bucket" "audit" {
  name                        = "audit-logs"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning {
    enabled = true
  }
}
