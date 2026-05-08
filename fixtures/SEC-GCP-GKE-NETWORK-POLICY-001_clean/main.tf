# Auto-generated clean fixture for SEC-GCP-GKE-NETWORK-POLICY-001.
# GKE cluster missing network_policy enforcement
# This is a CORRECT configuration; SEC-GCP-GKE-NETWORK-POLICY-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  network_policy {
    enabled  = true
    provider = "CALICO"
  }
  addons_config {
    network_policy_config { disabled = false }
  }
}
