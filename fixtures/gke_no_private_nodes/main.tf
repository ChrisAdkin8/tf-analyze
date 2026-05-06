# Expected findings:
#  - STK-GCP-GKE-001 HIGH — GKE cluster missing private_cluster_config.enable_private_nodes

resource "google_container_cluster" "no_private_nodes" {
  name     = "no-private-nodes"
  location = "us-central1"

  # No private_cluster_config block — nodes get public IPs.
  initial_node_count = 1

  workload_identity_config {
    workload_pool = "my-project.svc.id.goog"
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = "projects/my-project/locations/global/keyRings/k8s/cryptoKeys/secrets"
  }
}
