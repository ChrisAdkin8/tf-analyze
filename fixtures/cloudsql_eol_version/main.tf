# Expected findings:
#  - STK-GCP-CLOUDSQL-005 HIGH — Cloud SQL instance uses end-of-life database version

resource "google_sql_database_instance" "eol" {
  name             = "eol-postgres"
  region           = "us-central1"
  database_version = "POSTGRES_9_6"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = false
      require_ssl  = true
    }
    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = true
}
