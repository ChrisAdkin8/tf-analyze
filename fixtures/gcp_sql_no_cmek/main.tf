# Expected findings:
#  - SEC-GCP-SQL-CMEK-001 MEDIUM — no encryption_key_name (CMEK)

resource "google_sql_database_instance" "no_cmek" {
  name             = "app-db"
  region           = "us-central1"
  database_version = "POSTGRES_16"

  settings {
    tier                  = "db-custom-2-7680"
    disk_autoresize       = true
    disk_autoresize_limit = 50
    backup_configuration {
      enabled = true
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/example/global/networks/main"
      ssl_mode        = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }
  }

  deletion_protection = true
  # No encryption_key_name -- Google-managed key only.
}
