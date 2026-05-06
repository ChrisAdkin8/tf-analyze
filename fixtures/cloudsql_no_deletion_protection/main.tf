# Expected findings:
#  - STK-GCP-CLOUDSQL-003 HIGH — Cloud SQL instance missing deletion_protection

resource "google_sql_database_instance" "no_deletion_protection" {
  name             = "no-deletion-protection"
  region           = "us-central1"
  database_version = "POSTGRES_15"

  # deletion_protection absent — defaults to false, instance can be destroyed.
  settings {
    tier = "db-custom-2-7680"

    backup_configuration {
      enabled = true
    }

    ip_configuration {
      ipv4_enabled = false
    }
  }
}
