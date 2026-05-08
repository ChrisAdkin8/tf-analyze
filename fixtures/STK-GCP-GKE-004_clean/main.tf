# Auto-generated clean fixture for STK-GCP-GKE-004.
# GKE cluster missing master authorized networks
# This is a CORRECT configuration; STK-GCP-GKE-004 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/24"
      display_name = "corporate-vpn"
    }
  }
}
