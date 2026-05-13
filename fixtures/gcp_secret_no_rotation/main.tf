# Expected findings:
#  - SEC-GCP-SECRET-001 MEDIUM — no rotation block

resource "google_secret_manager_secret" "db_password" {
  secret_id = "db-password"
  replication {
    auto {}
  }
}
