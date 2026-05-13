# Expected findings:
#  - STK-GCP-PUBSUB-DLQ-001 MEDIUM — no dead_letter_policy

resource "google_pubsub_subscription" "no_dlq" {
  name  = "events-sub"
  topic = "events"
}
