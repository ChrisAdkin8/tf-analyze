# Auto-generated clean fixture for SEC-GCP-GKE-DBENC-001.
# GKE cluster missing application-layer secrets encryption (etcd CMEK)
# This is a CORRECT configuration; SEC-GCP-GKE-DBENC-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name               = "example"
  location           = "us-central1"
  initial_node_count = 1
  database_encryption {
    state    = "ENCRYPTED"
    key_name = "projects/example/locations/us-central1/keyRings/gke/cryptoKeys/etcd"
  }
}
