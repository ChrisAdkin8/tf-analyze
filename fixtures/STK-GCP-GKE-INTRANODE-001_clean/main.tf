# Auto-generated clean fixture for STK-GCP-GKE-INTRANODE-001.
# GKE cluster missing intra-node visibility
# This is a CORRECT configuration; STK-GCP-GKE-INTRANODE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name                        = "example"
  location                    = "us-central1"
  initial_node_count          = 1
  enable_intranode_visibility = true
}
