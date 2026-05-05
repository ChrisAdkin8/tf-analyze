# Expected findings:
#  - ROB-MOVED-001 LOW — stale moved block detected

resource "google_storage_bucket" "new_name" {
  name     = "my-bucket"
  location = "US"
}

moved {
  from = google_storage_bucket.old_name
  to   = google_storage_bucket.new_name
}
