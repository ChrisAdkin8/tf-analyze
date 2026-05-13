# Expected findings:
#  - SEC-GCP-SECRET-002 MEDIUM — replication.auto uses Google-managed key

resource "google_secret_manager_secret" "api_key" {
  secret_id = "api-key"
  replication {
    auto {}
  }
}
