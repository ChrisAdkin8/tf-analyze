# Auto-generated clean fixture for STK-GCP-FUNCTIONS-001.
# GCP Cloud Function uses end-of-life runtime
# This is a CORRECT configuration; STK-GCP-FUNCTIONS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloudfunctions2_function" "example" {
  name     = "example"
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
}
