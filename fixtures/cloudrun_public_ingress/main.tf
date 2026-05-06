# Expected findings:
#  - SEC-GCP-CLOUDRUN-001 HIGH — Cloud Run service allows all ingress traffic

resource "google_cloud_run_v2_service" "public" {
  name     = "public-service"
  location = "us-central1"
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello"
    }
  }
}
