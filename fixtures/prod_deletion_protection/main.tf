# Expected findings:
#  - OPS-ENV-001 HIGH — prod-scoped resource lacks deletion_protection

resource "google_sql_database_instance" "prod_db" {
  name             = "prod-primary"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"
  }

  labels = {
    environment = "prod"
  }
}
