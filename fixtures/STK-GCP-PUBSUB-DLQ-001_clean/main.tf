# Auto-generated clean fixture for STK-GCP-PUBSUB-DLQ-001.
# GCP Pub/Sub subscription missing dead_letter_policy
# This is a CORRECT configuration; STK-GCP-PUBSUB-DLQ-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_pubsub_subscription" "example" {
  name  = "events-sub"
  topic = google_pubsub_topic.events.name
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dlq.id
    max_delivery_attempts = 5
  }
}
