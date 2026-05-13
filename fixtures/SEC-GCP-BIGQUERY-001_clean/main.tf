# Auto-generated clean fixture for SEC-GCP-BIGQUERY-001.
# BigQuery dataset grants access to allUsers or allAuthenticatedUsers
# This is a CORRECT configuration; SEC-GCP-BIGQUERY-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_bigquery_dataset" "example" {
  dataset_id = "example"
  access {
    role           = "READER"
    group_by_email = "analysts@example.com"
  }
}
