# Auto-generated clean fixture for SEC-GCP-SCC-001.
# GCP Security Command Center notification not configured
# This is a CORRECT configuration; SEC-GCP-SCC-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_scc_notification_config" "all_findings" {
  config_id    = "all-findings"
  organization = var.org_id
  pubsub_topic = google_pubsub_topic.scc.id

  streaming_config {
    filter = "state = \"ACTIVE\""
  }
}
