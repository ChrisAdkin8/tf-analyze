# Auto-generated clean fixture for SEC-GCP-CLOUDRUN-003.
# GCP Cloud Run service uses default compute service account
# This is a CORRECT configuration; SEC-GCP-CLOUDRUN-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloud_run_v2_service" "example" {
  name     = "frontend"
  location = "us-central1"
  template {
    service_account = google_service_account.run.email
    containers { image = "gcr.io/example/app:1.0" }
  }
}
