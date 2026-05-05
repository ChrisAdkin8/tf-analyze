# Expected findings:
#  - STK-GKE-002 HIGH — cluster missing Workload Identity

resource "google_container_cluster" "main" {
  name                     = "main"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = true

  network_policy {
    enabled  = true
    provider = "CALICO"
  }
  # workload_identity_config intentionally omitted
}
