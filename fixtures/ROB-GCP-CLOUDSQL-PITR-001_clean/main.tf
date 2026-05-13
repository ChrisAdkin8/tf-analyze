# Auto-generated clean fixture for ROB-GCP-CLOUDSQL-PITR-001.
# Cloud SQL instance missing point-in-time recovery
# This is a CORRECT configuration; ROB-GCP-CLOUDSQL-PITR-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name             = "example"
  region           = "us-central1"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-custom-2-7680"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }
  }
}
