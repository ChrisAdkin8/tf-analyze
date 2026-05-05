# Expected findings: NONE
# Guards against: SEC-IAM-001
#
# SEC-IAM-001 was over-broad until we enumerated real GCP admin roles.
# Role names with "Admin" in them that are NOT in the admin set (e.g.
# roles/iap.tunnelResourceAccessor, roles/pubsub.subscriber) must not fire.

resource "google_project_iam_member" "narrow" {
  project = "my-project"
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:sa@my-project.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "narrow_access" {
  project = "my-project"
  role    = "roles/iap.tunnelResourceAccessor"
  member  = "user:dev@example.com"
}

resource "google_storage_bucket_iam_member" "reader" {
  bucket = "my-bucket"
  role   = "roles/storage.objectViewer"
  member = "user:reader@example.com"
}
