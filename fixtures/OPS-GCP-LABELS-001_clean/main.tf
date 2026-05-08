# Auto-generated clean fixture for OPS-GCP-LABELS-001.
# GCP resource missing labels block
# This is a CORRECT configuration; OPS-GCP-LABELS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_instance" "example" {
  # ... other arguments ...
  labels = {
    environment = "prod"
    owner       = "platform-team"
    project     = "my-project"
  }
}
