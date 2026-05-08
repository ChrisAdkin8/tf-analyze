# Auto-generated clean fixture for STK-GCP-GKE-001.
# GKE cluster missing private nodes
# This is a CORRECT configuration; STK-GCP-GKE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
  ip_allocation_policy {}
}
