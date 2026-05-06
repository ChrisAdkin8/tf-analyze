# Expected findings:
#   STK-GCP-ARTIFACT-001  MEDIUM  kms_key_name missing (Google-managed encryption only)

resource "google_artifact_registry_repository" "no_cmek" {
  location      = "us-central1"
  repository_id = "demo-no-cmek"
  format        = "DOCKER"
  # kms_key_name intentionally omitted — uses Google-managed encryption
}
