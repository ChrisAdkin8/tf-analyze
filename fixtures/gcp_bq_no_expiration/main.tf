# Expected findings:
#  - STK-GCP-BQ-EXPIRATION-001 LOW — no default_table_expiration_ms

resource "google_bigquery_dataset" "scratch" {
  dataset_id = "scratch"
  location   = "US"
}
