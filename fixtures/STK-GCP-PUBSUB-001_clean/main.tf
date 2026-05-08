# Auto-generated clean fixture for STK-GCP-PUBSUB-001.
# Pub/Sub topic missing customer-managed encryption key
# This is a CORRECT configuration; STK-GCP-PUBSUB-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_pubsub_topic" "example" {
  name         = "example"
  kms_key_name = google_kms_crypto_key.pubsub.id
}
