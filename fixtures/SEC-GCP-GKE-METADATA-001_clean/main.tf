# Auto-generated clean fixture for SEC-GCP-GKE-METADATA-001.
# GKE node pool missing GKE_METADATA workload metadata config (SSRF risk)
# This is a CORRECT configuration; SEC-GCP-GKE-METADATA-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_node_pool" "example" {
  name       = "main"
  cluster    = google_container_cluster.example.name
  node_count = 1
  node_config {
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
