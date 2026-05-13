# Expected findings:
#  - SEC-GCP-CLOUDRUN-002 CRITICAL — allUsers invoker binding

resource "google_cloud_run_service_iam_member" "public" {
  service  = "frontend"
  location = "us-central1"
  role     = "roles/run.invoker"
  member   = "allUsers"
}
