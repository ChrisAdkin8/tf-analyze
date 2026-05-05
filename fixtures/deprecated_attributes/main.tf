# Expected findings:
#  - STK-DEPRECATION-001 MEDIUM — deprecated logging_service argument

resource "google_container_cluster" "primary" {
  name     = "test-cluster"
  location = "us-central1"

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
}
