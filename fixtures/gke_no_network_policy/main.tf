# Expected findings:
#  - SEC-GCP-GKE-NETWORK-POLICY-001 HIGH — cluster missing network_policy

resource "google_container_cluster" "main" {
  name                     = "main"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1
  deletion_protection      = true
  # network_policy intentionally omitted
}
