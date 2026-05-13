# Expected findings:
#  - SEC-GCP-BQ-CMEK-001 MEDIUM — no encryption_configuration

resource "google_bigquery_table" "no_cmek" {
  dataset_id = "analytics"
  table_id   = "events"
}
