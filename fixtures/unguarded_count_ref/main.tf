# Expected findings:
#  - ROB-COUNTREF-001 MEDIUM — unguarded reference to count-conditional resource

variable "create_db" {
  type    = bool
  default = false
}

resource "google_sql_database_instance" "optional" {
  count = var.create_db ? 1 : 0

  name             = "optional-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
  }
}

# Unguarded [0] reference — finding
output "db_connection" {
  value = google_sql_database_instance.optional[0].connection_name
}

# Guarded reference — OK, no finding
output "db_ip" {
  value = var.create_db ? google_sql_database_instance.optional[0].private_ip_address : null
}
