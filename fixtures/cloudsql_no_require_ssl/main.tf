# Expected findings:
#  - STK-GCP-CLOUDSQL-004 HIGH — Cloud SQL instance does not require SSL connections

resource "google_sql_database_instance" "no_ssl" {
  name             = "no-ssl"
  region           = "us-central1"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = false
      # require_ssl intentionally omitted — defaults to false — STK-GCP-CLOUDSQL-004 fires.
    }
    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = true
}
