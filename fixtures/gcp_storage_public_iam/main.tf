# Expected findings:
#  - SEC-GCP-STORAGE-IAM-001 CRITICAL — allUsers binding

resource "google_storage_bucket_iam_member" "public" {
  bucket = "shared-assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
