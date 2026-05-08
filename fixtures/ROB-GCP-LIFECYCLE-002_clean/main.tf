# Auto-generated clean fixture for ROB-GCP-LIFECYCLE-002.
# Stateful resource has force_destroy=true
# This is a CORRECT configuration; ROB-GCP-LIFECYCLE-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_storage_bucket" "example" {
  name          = "example"
  location      = "US"
  force_destroy = false
}
