# Expected findings:
#  - SEC-GCP-CLOUDRUN-003 HIGH — no service_account (uses default compute SA)

resource "google_cloud_run_v2_service" "default_sa" {
  name     = "frontend"
  location = "us-central1"
  template {
    containers {
      image = "gcr.io/example/app:1.0"
    }
  }
}
