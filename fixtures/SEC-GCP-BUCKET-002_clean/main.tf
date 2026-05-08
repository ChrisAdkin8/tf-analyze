# Auto-generated clean fixture for SEC-GCP-BUCKET-002.
# GCS bucket missing uniform_bucket_level_access
# This is a CORRECT configuration; SEC-GCP-BUCKET-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket" "example" {
  name                        = "example"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
