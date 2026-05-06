# Expected findings:
#  - STK-GCP-BIGQUERY-001 HIGH — BigQuery dataset missing default_encryption_configuration.kms_key_name

resource "google_bigquery_dataset" "analytics" {
  dataset_id = "analytics"
  location   = "US"

  # No default_encryption_configuration — tables use Google-managed keys.
}
