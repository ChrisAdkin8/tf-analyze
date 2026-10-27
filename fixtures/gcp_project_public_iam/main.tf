# Expected findings:
#  - SEC-GCP-IAM-002 CRITICAL — project-level binding to allUsers
# (Cloud Storage bindings are SEC-GCP-STORAGE-IAM-001)

resource "google_project_iam_member" "public_viewer" {
  project = "my-project"
  role    = "roles/viewer"
  member  = "allUsers"
}
