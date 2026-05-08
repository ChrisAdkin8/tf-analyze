# Auto-generated clean fixture for STK-GCP-CLOUDSQL-001.
# Cloud SQL instance missing backup_configuration
# This is a CORRECT configuration; STK-GCP-CLOUDSQL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled                        = true
      start_time                     = "02:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 7
      }
    }
  }
}
