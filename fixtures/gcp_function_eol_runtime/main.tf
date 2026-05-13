# Expected findings:
#  - STK-GCP-FUNCTIONS-001 HIGH — runtime = "python37" (EOL)

resource "google_cloudfunctions_function" "eol" {
  name        = "process-events"
  description = "EOL runtime"
  runtime     = "python37"

  available_memory_mb = 256
  source_archive_bucket = "build-artifacts"
  source_archive_object = "src.zip"
  entry_point           = "main"
  trigger_http          = true
}
