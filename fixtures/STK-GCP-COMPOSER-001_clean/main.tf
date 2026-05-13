# Auto-generated clean fixture for STK-GCP-COMPOSER-001.
# GCP Composer (Airflow) environment not private
# This is a CORRECT configuration; STK-GCP-COMPOSER-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_composer_environment" "example" {
  name   = "example"
  region = "us-central1"
  config {
    private_environment_config {
      enable_private_endpoint = true
    }
  }
}
