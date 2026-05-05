# Expected findings:
#  - STK-CLOUDSQL-001 HIGH — google_sql_database_instance has no
#    settings.backup_configuration.enabled (CIS GCP 6.4)

terraform {
  required_version = "~> 1.10"
}

resource "google_sql_database_instance" "main" {
  name             = "test-instance"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    # finding: no backup_configuration block
  }

  deletion_protection = false
}
