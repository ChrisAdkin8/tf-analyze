# Expected findings:
#  - SEC-LOGGING-001 HIGH — no google_project_iam_audit_config resource exists,
#    so Cloud Audit Logs are not configured (CIS GCP 2.1)

terraform {
  required_version = "~> 1.10"
}

# A bare project resource with no audit config — the absence is the finding.
resource "google_project" "test" {
  name       = "test-project"
  project_id = "test-project"
  org_id     = "123456789012"
}
