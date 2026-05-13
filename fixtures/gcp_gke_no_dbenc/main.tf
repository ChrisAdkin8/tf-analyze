# Expected findings:
#  - SEC-GCP-GKE-DBENC-001 HIGH — no database_encryption (etcd CMEK)

resource "google_container_cluster" "no_dbenc" {
  name                     = "data-cluster"
  location                 = "us-central1"
  initial_node_count       = 1
  remove_default_node_pool = true
}
