# Auto-generated clean fixture for COST-GCP-RISK-001.
# Expensive resource without cost control
# This is a CORRECT configuration; COST-GCP-RISK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_spanner_instance" "app" {
  config           = "regional-us-central1"
  display_name     = "app"
  processing_units = 100
}

resource "google_sql_database_instance" "app" {
  settings {
    tier                   = "db-f1-micro"
    disk_autoresize        = true
    disk_autoresize_limit  = 50
  }
}
