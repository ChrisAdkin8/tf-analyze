# Expected findings:
#  - STK-BUCKET-001 MEDIUM — bucket missing versioning

resource "google_storage_bucket" "data" {
  name                        = "data"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  # versioning block intentionally omitted

  lifecycle {
    prevent_destroy = true
  }
}
