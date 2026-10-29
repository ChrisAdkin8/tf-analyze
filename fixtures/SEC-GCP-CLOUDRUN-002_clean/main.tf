# Auto-generated clean fixture for SEC-GCP-CLOUDRUN-002.
# GCP Cloud Run service publicly accessible (allUsers IAM binding)
# This is a CORRECT configuration; SEC-GCP-CLOUDRUN-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloud_run_service_iam_member" "invoker" {
  service  = google_cloud_run_service.example.name
  location = google_cloud_run_service.example.location
  role     = "roles/run.invoker"
  member   = "group:authenticated-callers@example.com"
}

resource "google_cloud_run_service_iam_binding" "invokers" {
  service  = google_cloud_run_service.example.name
  location = google_cloud_run_service.example.location
  role     = "roles/run.invoker"
  members  = ["group:authenticated-callers@example.com"]
}

resource "google_cloud_run_v2_service_iam_binding" "invokers" {
  name     = "frontend-v2"
  location = "us-central1"
  role     = "roles/run.invoker"
  members  = ["serviceAccount:caller@my-project.iam.gserviceaccount.com"]
}
