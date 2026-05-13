# Expected findings:
#  - STK-GCP-ARTIFACT-002 MEDIUM — no cleanup_policies block

resource "google_artifact_registry_repository" "no_cleanup" {
  location      = "us-central1"
  repository_id = "app-images"
  format        = "DOCKER"
  description   = "Docker images for app"
  # No cleanup_policies -- untagged manifests pile up indefinitely.
}
