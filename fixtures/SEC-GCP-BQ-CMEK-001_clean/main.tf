# Auto-generated clean fixture for SEC-GCP-BQ-CMEK-001.
# BigQuery table not encrypted with customer-managed key
# This is a CORRECT configuration; SEC-GCP-BQ-CMEK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_bigquery_table" "example" {
  dataset_id = google_bigquery_dataset.example.dataset_id
  table_id   = "example"
  encryption_configuration {
    kms_key_name = "projects/example/locations/us/keyRings/bq/cryptoKeys/data"
  }
}
