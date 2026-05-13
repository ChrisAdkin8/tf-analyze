# Auto-generated clean fixture for STK-GCP-CLOUDTASKS-001.
# GCP Cloud Tasks queue missing rate or retry configuration
# This is a CORRECT configuration; STK-GCP-CLOUDTASKS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloud_tasks_queue" "example" {
  name     = "example"
  location = "us-central1"
  rate_limits {
    max_dispatches_per_second = 50
    max_concurrent_dispatches = 100
  }
  retry_config {
    max_attempts = 5
    min_backoff  = "1s"
    max_backoff  = "60s"
  }
}
