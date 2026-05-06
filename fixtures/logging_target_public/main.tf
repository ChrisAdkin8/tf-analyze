# Expected findings:
#  - STK-GCP-GCS-LOGGING-001 HIGH — logging target bucket lacks public_access_prevention

resource "google_storage_bucket" "data" {
  name                        = "my-data"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  logging {
    log_bucket = google_storage_bucket.audit.name
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "audit" {
  name                        = "my-audit"
  location                    = "US"
  uniform_bucket_level_access = true
  # public_access_prevention intentionally omitted to trigger the graph check

  lifecycle {
    prevent_destroy = true
  }
}
