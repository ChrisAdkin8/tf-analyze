# Expected findings:
#  - STK-GCP-GKE-NODEPOOL-001 HIGH — node pool missing shielded-instance hardening

resource "google_container_cluster" "main" {
  name               = "main"
  location           = "us-central1"
  remove_default_node_pool = true
  initial_node_count = 1
}

resource "google_container_node_pool" "default" {
  name     = "default"
  cluster  = google_container_cluster.main.name
  location = "us-central1"

  node_config {
    machine_type = "e2-medium"
    # shielded_instance_config intentionally omitted — STK-GCP-GKE-NODEPOOL-001 should fire
  }
}
