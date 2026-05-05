# Expected findings:
#  - ROB-REMOVED-001 LOW — stale removed block (TF 1.7+)

terraform {
  required_version = ">= 1.7.0"
}

removed {
  from = google_storage_bucket.deprecated_data
  lifecycle {
    destroy = true
  }
}
