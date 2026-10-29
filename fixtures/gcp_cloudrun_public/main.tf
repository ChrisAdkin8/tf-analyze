# Expected findings:
#  - SEC-GCP-CLOUDRUN-002 CRITICAL — allUsers invoker binding
#  - SEC-GCP-CLOUDRUN-002 CRITICAL — authoritative invoker binding (v1)
#  - SEC-GCP-CLOUDRUN-002 CRITICAL — authoritative invoker binding (v2)

resource "google_cloud_run_service_iam_member" "public" {
  service  = "frontend"
  location = "us-central1"
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_service_iam_binding" "public" {
  service  = "frontend"
  location = "us-central1"
  role     = "roles/run.invoker"
  members  = ["allUsers"]
}

resource "google_cloud_run_v2_service_iam_binding" "public" {
  name     = "frontend-v2"
  location = "us-central1"
  role     = "roles/run.invoker"
  members  = ["allUsers"]
}
