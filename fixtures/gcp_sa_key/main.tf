# Expected findings: SEC-GCP-SA-KEY-001

resource "google_service_account" "app" {
  account_id   = "demo-app"
  display_name = "Demo App"
  project      = "my-project"
}

# Creating a static key bakes the private key into Terraform state.
resource "google_service_account_key" "app_key" {
  service_account_id = google_service_account.app.name
}
