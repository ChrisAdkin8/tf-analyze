# Storage section — exercises SEC-BUCKET-001/002, STK-BUCKET-001,
# OPS-ENV-001, ROB-LIFECYCLE-001, STK-GCS-LOGGING-001.

# SEC-BUCKET-001 HIGH (no public_access_prevention=enforced)
# SEC-BUCKET-002 MEDIUM (no uniform_bucket_level_access)
# STK-BUCKET-001 MEDIUM (no versioning)
# ROB-LIFECYCLE-001 HIGH (no lifecycle.prevent_destroy on a stateful bucket)
# OPS-ENV-001 HIGH (label environment=prod, no deletion_protection equivalent)
resource "google_storage_bucket" "data" {
  name     = "demo-prod-data"
  location = "US"

  labels = {
    environment = "prod"
  }

  logging {
    log_bucket = google_storage_bucket.audit.name
  }
}

# STK-GCS-LOGGING-001 HIGH — logging target lacks public_access_prevention
# (targets the bucket above; the rule walks logging.log_bucket → audit
# and checks audit's settings).
resource "google_storage_bucket" "audit" {
  name                        = "demo-audit-logs"
  location                    = "US"
  uniform_bucket_level_access = true
  # public_access_prevention intentionally omitted — should fire
  # STK-GCS-LOGGING-001 because this bucket receives access logs from
  # `data` above.

  versioning {
    enabled = true
  }
}
