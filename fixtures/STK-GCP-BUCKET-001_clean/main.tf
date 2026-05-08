# Auto-generated clean fixture for STK-GCP-BUCKET-001.
# GCS bucket missing versioning
# This is a CORRECT configuration; STK-GCP-BUCKET-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket" "example" {
  name     = "example"
  location = "US"
  versioning {
    enabled = true
  }
}
