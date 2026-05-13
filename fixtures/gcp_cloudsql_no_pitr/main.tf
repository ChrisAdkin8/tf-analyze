# Expected findings:
#  - ROB-GCP-CLOUDSQL-PITR-001 MEDIUM — point_in_time_recovery_enabled = false

resource "google_sql_database_instance" "no_pitr" {
  name             = "primary"
  region           = "us-central1"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = false
    }
  }

  deletion_protection = true
}
