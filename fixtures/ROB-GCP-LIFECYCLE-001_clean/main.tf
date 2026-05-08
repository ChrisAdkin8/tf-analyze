# Auto-generated clean fixture for ROB-GCP-LIFECYCLE-001.
# Stateful resource missing lifecycle.prevent_destroy
# This is a CORRECT configuration; ROB-GCP-LIFECYCLE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_sql_database_instance" "example" {
  # ... other arguments ...
  lifecycle {
    prevent_destroy = true
  }
}
