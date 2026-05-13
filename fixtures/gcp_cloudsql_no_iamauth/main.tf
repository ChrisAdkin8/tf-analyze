# Expected findings:
#  - STK-GCP-CLOUDSQL-IAMAUTH-001 MEDIUM — no database_flags (no IAM auth)

resource "google_sql_database_instance" "no_iam" {
  name             = "primary"
  region           = "us-central1"
  database_version = "POSTGRES_16"

  settings {
    tier = "db-custom-2-7680"
    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = true
}
