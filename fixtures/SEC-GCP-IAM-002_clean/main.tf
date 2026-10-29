# Auto-generated clean fixture for SEC-GCP-IAM-002.
# Public IAM binding (allUsers / allAuthenticatedUsers)
# This is a CORRECT configuration; SEC-GCP-IAM-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket_iam_member" "example" {
  bucket = google_storage_bucket.example.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.example.email}"
}

# The authoritative form, with only named principals.
resource "google_project_iam_binding" "viewers" {
  project = "my-project"
  role    = "roles/viewer"
  members = [
    "group:viewers@example.com",
    "serviceAccount:${google_service_account.example.email}",
  ]
}
