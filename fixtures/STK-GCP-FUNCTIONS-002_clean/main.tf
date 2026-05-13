# Auto-generated clean fixture for STK-GCP-FUNCTIONS-002.
# GCP Cloud Function uses default service account
# This is a CORRECT configuration; STK-GCP-FUNCTIONS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_service_account" "fn" {
  account_id   = "fn-process-events"
  display_name = "process-events function"
}

resource "google_cloudfunctions2_function" "example" {
  name     = "process-events"
  location = "us-central1"

  build_config {
    runtime     = "python312"
    entry_point = "main"
    source {
      storage_source {
        bucket = google_storage_bucket.source.name
        object = "source.zip"
      }
    }
  }

  service_config {
    service_account_email = google_service_account.fn.email
  }
}
