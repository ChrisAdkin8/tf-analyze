# GKE section — exercises STK-GKE-NODEPOOL-001, STK-GKE-002,
# SEC-GKE-NETWORK-POLICY-001.

# STK-GKE-002 HIGH — missing workload_identity_config (no WI).
# SEC-GKE-NETWORK-POLICY-001 HIGH — missing network_policy block.
resource "google_container_cluster" "demo" {
  name                     = "demo-cluster"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = true

  # workload_identity_config intentionally omitted
  # network_policy intentionally omitted
}

# STK-GKE-NODEPOOL-001 HIGH — node pool missing
# shielded_instance_config.enable_secure_boot.
resource "google_container_node_pool" "default" {
  name     = "default"
  cluster  = google_container_cluster.demo.name
  location = "us-central1"

  node_config {
    machine_type = "e2-medium"
    # No shielded_instance_config block
  }
}
