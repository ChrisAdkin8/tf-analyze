# Expected findings:
#  - STK-GCP-GKE-RELEASE-001 MEDIUM — release_channel.channel = UNSPECIFIED

resource "google_container_cluster" "static" {
  name               = "static-cluster"
  location           = "us-central1"
  initial_node_count = 1
  release_channel {
    channel = "UNSPECIFIED"
  }
}
