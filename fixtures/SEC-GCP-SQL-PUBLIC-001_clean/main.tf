# Auto-generated clean fixture for SEC-GCP-SQL-PUBLIC-001.
# Cloud SQL instance permits public IPv4
# This is a CORRECT configuration; SEC-GCP-SQL-PUBLIC-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_14"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}
