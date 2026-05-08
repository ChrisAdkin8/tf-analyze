# Auto-generated clean fixture for SEC-GCP-IAM-001.
# Project-level binding of overly broad role
# This is a CORRECT configuration; SEC-GCP-IAM-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_project_iam_member" "example" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.example.email}"
}
