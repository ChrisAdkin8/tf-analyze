# Expected findings:
#  - SEC-GCP-SCC-001 HIGH — no google_scc_notification_config declared

resource "google_compute_network" "main" {
  name                    = "main"
  auto_create_subnetworks = false
}

resource "google_pubsub_topic" "ingest" {
  name = "ingest-events"
}
