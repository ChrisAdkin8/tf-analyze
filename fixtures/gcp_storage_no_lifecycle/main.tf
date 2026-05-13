# Expected findings:
#  - STK-GCP-STORAGE-LIFECYCLE-001 LOW — no lifecycle_rule

resource "google_storage_bucket" "no_lifecycle" {
  name                        = "app-cache"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
