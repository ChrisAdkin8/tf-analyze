# Auto-generated clean fixture for STK-GCP-GKE-RELEASE-001.
# GKE cluster on STATIC release channel (no auto-upgrade)
# This is a CORRECT configuration; STK-GCP-GKE-RELEASE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name               = "example"
  location           = "us-central1"
  initial_node_count = 1
  release_channel {
    channel = "REGULAR"
  }
}
