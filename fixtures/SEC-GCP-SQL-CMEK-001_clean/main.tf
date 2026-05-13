# Auto-generated clean fixture for SEC-GCP-SQL-CMEK-001.
# Cloud SQL instance not encrypted with customer-managed key (CMEK)
# This is a CORRECT configuration; SEC-GCP-SQL-CMEK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name                = "example"
  region              = "us-central1"
  database_version    = "POSTGRES_16"
  encryption_key_name = google_kms_crypto_key.sql.id
  settings {
    tier = "db-custom-2-7680"
  }
}
