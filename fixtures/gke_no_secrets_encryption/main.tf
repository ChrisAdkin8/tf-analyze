# Expected findings:
#  - STK-GCP-GKE-003 HIGH — GKE cluster missing database_encryption.state

resource "google_container_cluster" "no_secrets_encryption" {
  name     = "no-secrets-encryption"
  location = "us-central1"

  # No database_encryption block — etcd secrets are not application-layer encrypted.
  initial_node_count = 1

  workload_identity_config {
    workload_pool = "my-project.svc.id.goog"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
}
