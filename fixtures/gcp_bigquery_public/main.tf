# Expected findings:
#  - SEC-GCP-BIGQUERY-001 CRITICAL — special_group = allAuthenticatedUsers

resource "google_bigquery_dataset" "public" {
  dataset_id = "public_data"
  location   = "US"

  access {
    role          = "READER"
    special_group = "allAuthenticatedUsers"
  }
}
