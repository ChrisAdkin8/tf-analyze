# Expected findings:
#  - STK-GCP-GKE-003 HIGH — database_encryption present but DECRYPTED
# (no database_encryption block at all is SEC-GCP-GKE-DBENC-001)

resource "google_container_cluster" "no_secrets_encryption" {
  name     = "no-secrets-encryption"
  location = "us-central1"

  initial_node_count = 1

  # Present but turned off — etcd secrets are not application-layer encrypted.
  database_encryption {
    state    = "DECRYPTED"
    key_name = ""
  }

  workload_identity_config {
    workload_pool = "my-project.svc.id.goog"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
}
