# Auto-generated clean fixture for STK-GCP-BIGQUERY-001.
# BigQuery dataset missing default CMEK
# This is a CORRECT configuration; STK-GCP-BIGQUERY-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_bigquery_dataset" "example" {
  dataset_id = "example"
  location   = "US"
  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.bq.id
  }
}
