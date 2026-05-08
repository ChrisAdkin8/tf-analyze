# Auto-generated clean fixture for STK-GCP-GKE-002.
# GKE cluster missing Workload Identity
# This is a CORRECT configuration; STK-GCP-GKE-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_container_cluster" "example" {
  name     = "example"
  location = "us-central1"
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
}
