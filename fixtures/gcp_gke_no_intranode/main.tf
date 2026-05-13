# Expected findings:
#  - STK-GCP-GKE-INTRANODE-001 LOW — no enable_intranode_visibility

resource "google_container_cluster" "no_intranode" {
  name               = "obs-cluster"
  location           = "us-central1"
  initial_node_count = 1
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
}
