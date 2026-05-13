# Auto-generated clean fixture for STK-GCP-CLOUDRUN-001.
# GCP Cloud Run service has unbounded container concurrency
# This is a CORRECT configuration; STK-GCP-CLOUDRUN-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloud_run_v2_service" "example" {
  name     = "frontend"
  location = "us-central1"
  template {
    max_instance_request_concurrency = 80
    containers { image = "gcr.io/example/app:1.0" }
  }
}
