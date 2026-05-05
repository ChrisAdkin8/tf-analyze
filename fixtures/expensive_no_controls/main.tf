# Expected findings:
#  - COST-RISK-001 MEDIUM — Spanner instance without processing_units
#  - COST-RISK-001 MEDIUM — Cloud SQL without disk_autoresize_limit

resource "google_spanner_instance" "test" {
  name         = "test-instance"
  config       = "regional-us-central1"
  display_name = "Test"
}

resource "google_sql_database_instance" "test" {
  name             = "test-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
  }
}
