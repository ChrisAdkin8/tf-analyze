# Expected findings:
#  - STK-GCP-CLOUDRUN-001 MEDIUM — max_instance_request_concurrency = 0 (unbounded)

resource "google_cloud_run_v2_service" "unbounded" {
  name     = "backend"
  location = "us-central1"
  template {
    max_instance_request_concurrency = 0
    service_account                  = "run-svc@example.iam.gserviceaccount.com"
    containers {
      image = "gcr.io/example/app:1.0"
    }
  }
}
