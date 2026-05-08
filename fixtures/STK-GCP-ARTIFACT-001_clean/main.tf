# Auto-generated clean fixture for STK-GCP-ARTIFACT-001.
# Artifact Registry repository missing customer-managed encryption key
# This is a CORRECT configuration; STK-GCP-ARTIFACT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_artifact_registry_repository" "example" {
  location      = "us-central1"
  repository_id = "example"
  format        = "DOCKER"
  kms_key_name  = google_kms_crypto_key.artifact.id
}
