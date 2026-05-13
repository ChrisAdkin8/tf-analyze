# Auto-generated clean fixture for STK-GCP-CLOUDBUILD-001.
# GCP Cloud Build trigger missing manual approval
# This is a CORRECT configuration; STK-GCP-CLOUDBUILD-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_cloudbuild_trigger" "example" {
  name        = "prod-deploy"
  filename    = "cloudbuild.yaml"
  description = "Production deployment"
  github {
    owner = "example"
    name  = "infra"
    push {
      branch = "^main$"
    }
  }
  approval_config {
    approval_required = true
  }
}
