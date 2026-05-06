# Expected findings:
#  - STK-GCP-GKE-004 HIGH — GKE cluster missing master_authorized_networks_config.cidr_blocks

resource "google_container_cluster" "no_master_auth" {
  name     = "no-master-auth"
  location = "us-central1"

  # No master_authorized_networks_config — API server reachable from any IP.
  initial_node_count = 1

  workload_identity_config {
    workload_pool = "my-project.svc.id.goog"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  database_encryption {
    state    = "ENCRYPTED"
    key_name = "projects/my-project/locations/global/keyRings/k8s/cryptoKeys/secrets"
  }
}
