# Expected findings:
#  - STK-GCP-FUNCTIONS-002 HIGH — no service_account_email (runs as default SA)

resource "google_cloudfunctions_function" "default_sa" {
  name                  = "process-events"
  runtime               = "python312"
  available_memory_mb   = 256
  source_archive_bucket = "build-artifacts"
  source_archive_object = "src.zip"
  entry_point           = "main"
  trigger_http          = true
  # No service_account_email -- inherits the over-privileged App Engine default SA.
}
