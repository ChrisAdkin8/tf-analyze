# Expected findings:
#  - SEC-GCP-SPANNER-001 MEDIUM — no encryption_config

resource "google_spanner_database" "no_cmek" {
  instance = "app-instance"
  name     = "main"
}
