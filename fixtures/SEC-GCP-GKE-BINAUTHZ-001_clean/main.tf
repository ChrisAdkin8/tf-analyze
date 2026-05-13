# Auto-generated clean fixture for SEC-GCP-GKE-BINAUTHZ-001.
# GKE cluster missing Binary Authorization
# This is a CORRECT configuration; SEC-GCP-GKE-BINAUTHZ-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  initial_node_count = 1
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
}
