# Expected findings:
#  - SEC-IAM-003 HIGH — member has both project-level AND resource-level IAM

resource "google_project_iam_member" "broad" {
  project = "my-project"
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}

resource "google_storage_bucket_iam_member" "narrow" {
  bucket = "my-bucket"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}
