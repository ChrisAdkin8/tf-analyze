# Expected findings:
#  - SEC-GCP-GKE-BINAUTHZ-001 HIGH — no binary_authorization

resource "google_container_cluster" "no_binauthz" {
  name               = "app-cluster"
  location           = "us-central1"
  initial_node_count = 1
  remove_default_node_pool = true
}
