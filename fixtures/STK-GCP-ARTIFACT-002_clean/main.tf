# Auto-generated clean fixture for STK-GCP-ARTIFACT-002.
# GCP Artifact Registry missing cleanup policy
# This is a CORRECT configuration; STK-GCP-ARTIFACT-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_artifact_registry_repository" "example" {
  location      = "us-central1"
  repository_id = "example"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-untagged-7d"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s"
    }
  }
}
