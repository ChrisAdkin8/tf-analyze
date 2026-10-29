# Expected findings:
#  - SEC-GCP-IAM-002 CRITICAL — project-level binding to allUsers
#  - SEC-GCP-IAM-002 CRITICAL — authoritative binding whose members list
#    includes allAuthenticatedUsers
# (Cloud Storage bindings are SEC-GCP-STORAGE-IAM-001)

resource "google_project_iam_member" "public_viewer" {
  project = "my-project"
  role    = "roles/viewer"
  member  = "allUsers"
}

resource "google_project_iam_binding" "public_browser" {
  project = "my-project"
  role    = "roles/browser"
  members = [
    "group:admins@example.com",
    "allAuthenticatedUsers",
  ]
}
