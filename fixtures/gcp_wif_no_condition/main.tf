# Expected findings:
#  - SEC-GCP-WIF-001 CRITICAL — no attribute_condition (any caller can mint a token)

resource "google_iam_workload_identity_pool" "gh" {
  workload_identity_pool_id = "gh-actions"
}

resource "google_iam_workload_identity_pool_provider" "any_repo" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.gh.workload_identity_pool_id
  workload_identity_pool_provider_id = "any-repo"
  display_name                       = "Any GitHub Repo"

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
  # No attribute_condition -- any GitHub workflow can mint a Google token.
}
