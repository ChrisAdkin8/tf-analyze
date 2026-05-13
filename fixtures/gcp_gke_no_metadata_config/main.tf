# Expected findings:
#  - SEC-GCP-GKE-METADATA-001 HIGH — no workload_metadata_config (SSRF risk)

resource "google_container_node_pool" "no_md" {
  name       = "main"
  cluster    = "app-cluster"
  location   = "us-central1"
  node_count = 3
  node_config {
    machine_type    = "e2-standard-4"
    service_account = "node-sa@example.iam.gserviceaccount.com"
  }
}
