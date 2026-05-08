# Auto-generated clean fixture for STK-GCP-CLOUDSQL-003.
# Cloud SQL instance missing deletion protection
# This is a CORRECT configuration; STK-GCP-CLOUDSQL-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_15"
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
  }
}
