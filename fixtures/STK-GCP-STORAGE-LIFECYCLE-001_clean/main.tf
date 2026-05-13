# Auto-generated clean fixture for STK-GCP-STORAGE-LIFECYCLE-001.
# GCS bucket missing lifecycle_rule (object accumulation)
# This is a CORRECT configuration; STK-GCP-STORAGE-LIFECYCLE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket" "example" {
  name                        = "app-cache"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  lifecycle_rule {
    condition { age = 90 }
    action {
      type = "Delete"
    }
  }
}
