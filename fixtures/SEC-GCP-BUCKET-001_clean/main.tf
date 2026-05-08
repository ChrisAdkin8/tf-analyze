# Auto-generated clean fixture for SEC-GCP-BUCKET-001.
# GCS bucket missing public_access_prevention=enforced
# This is a CORRECT configuration; SEC-GCP-BUCKET-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket" "example" {
  name                        = "example"
  location                    = "US"
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true
}
