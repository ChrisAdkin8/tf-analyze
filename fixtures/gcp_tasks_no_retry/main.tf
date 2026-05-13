# Expected findings:
#  - STK-GCP-CLOUDTASKS-001 LOW — no retry_config / no rate_limits

resource "google_cloud_tasks_queue" "no_retry" {
  name     = "ingest"
  location = "us-central1"
}
