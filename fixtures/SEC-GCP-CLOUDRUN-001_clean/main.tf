# Auto-generated clean fixture for SEC-GCP-CLOUDRUN-001.
# Cloud Run service allows all ingress traffic
# This is a CORRECT configuration; SEC-GCP-CLOUDRUN-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloud_run_v2_service" "example" {
  name     = "example"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  template {
    containers {
      image = "gcr.io/example/app:latest"
    }
  }
}
