# Auto-generated clean fixture for STK-GCP-CLOUDSQL-004.
# Cloud SQL instance does not require SSL connections
# This is a CORRECT configuration; STK-GCP-CLOUDSQL-004 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  # ... other arguments ...
  settings {
    ip_configuration {
      ssl_mode = "ENCRYPTED_ONLY"
    }
  }
}
