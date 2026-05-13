# Auto-generated clean fixture for SEC-GCP-WIF-001.
# GCP Workload Identity Federation pool provider missing attribute_condition
# This is a CORRECT configuration; SEC-GCP-WIF-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.gh.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-actions"
  display_name                       = "GitHub Actions"

  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.repository"  = "assertion.repository"
  }

  attribute_condition = "assertion.repository == 'my-org/my-repo'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
