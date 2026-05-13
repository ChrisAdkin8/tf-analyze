# Expected findings:
#  - STK-GCP-COMPOSER-001 HIGH — no private_environment_config

resource "google_composer_environment" "no_priv" {
  name   = "airflow"
  region = "us-central1"
}
