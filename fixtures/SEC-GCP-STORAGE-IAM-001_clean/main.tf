# Auto-generated clean fixture for SEC-GCP-STORAGE-IAM-001.
# GCS bucket bound to allUsers or allAuthenticatedUsers
# This is a CORRECT configuration; SEC-GCP-STORAGE-IAM-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket_iam_member" "example" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "group:viewers@example.com"
}
