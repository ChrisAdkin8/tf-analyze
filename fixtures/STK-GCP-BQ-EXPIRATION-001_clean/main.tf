# Auto-generated clean fixture for STK-GCP-BQ-EXPIRATION-001.
# BigQuery dataset missing default_table_expiration_ms (cost runaway)
# This is a CORRECT configuration; STK-GCP-BQ-EXPIRATION-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_bigquery_dataset" "example" {
  dataset_id                  = "scratch"
  location                    = "US"
  default_table_expiration_ms = 2592000000
}
