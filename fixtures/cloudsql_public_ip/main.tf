# Expected findings:
#  - SEC-GCP-SQL-PUBLIC-001 HIGH — Cloud SQL instance has ipv4_enabled = true

resource "google_sql_database_instance" "main" {
  name             = "main"
  region           = "us-central1"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
    }

    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = true
}
