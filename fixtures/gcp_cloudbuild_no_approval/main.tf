# Expected findings:
#  - STK-GCP-CLOUDBUILD-001 MEDIUM — no approval_config

resource "google_cloudbuild_trigger" "auto" {
  name     = "main-push"
  filename = "cloudbuild.yaml"
  github {
    owner = "example"
    name  = "infra"
    push {
      branch = "^main$"
    }
  }
}
