# Auto-generated clean fixture for STK-GCP-CLOUDSQL-005.
# Cloud SQL instance uses end-of-life database version
# This is a CORRECT configuration; STK-GCP-CLOUDSQL-005 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-f1-micro"
  }
}
