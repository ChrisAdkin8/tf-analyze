# OWASP A01:2021 — Broken Access Control
# Cloud: GCP
#
# Broken access control on GCP usually shows up as IAM bindings whose
# scope or membership is wider than the workload requires. Three of the
# most common failures are demonstrated below: organisation-level
# admin grants, public principals on resource IAM, and the same member
# bound at both project and resource level (the project-level grant
# silently supersedes the resource-level one, defeating the apparent
# narrow scoping).
#
# Real-world impact:
#   - `roles/owner` at project level lets the holder delete the
#     project, including state buckets and audit logs (eliminating the
#     forensic trail of their own actions).
#   - `allUsers` on a bucket means any anonymous internet client can
#     list and read every object — credential leaks here are minutes,
#     not weeks, after exposure.
#   - The double-grant pattern hides over-privilege from auditors who
#     only inspect resource-level IAM.
#
# Expected tf-analyze findings:
#   - SEC-GCP-IAM-001     HIGH       Project-level binding of overly broad role
#   - SEC-GCP-IAM-002     CRITICAL   Public IAM binding (allUsers)
#   - SEC-GCP-IAM-003     HIGH       Member has both project-level and resource-level IAM grants
#
# Fix summary: bind narrow roles at the resource level using
# `google_<service>_iam_member`. If the workload genuinely needs
# project-wide access, use IAM Conditions to scope by tag or time
# rather than reaching for an admin role.

resource "google_project_iam_member" "admin_too_broad" {
  project = "demo-project"
  role    = "roles/owner"
  member  = "user:admin@example.com"
}

resource "google_storage_bucket_iam_member" "public_objects" {
  bucket = "demo-public-bucket"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# Same member at project AND resource scope — over-privilege smell.
resource "google_project_iam_member" "app_at_project" {
  project = "demo-project"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:app@demo-project.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "app_at_bucket" {
  bucket = "demo-data"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:app@demo-project.iam.gserviceaccount.com"
}
