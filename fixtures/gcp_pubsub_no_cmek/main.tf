resource "google_pubsub_topic" "no_cmek" {
  name = "app-events"
  # kms_key_name intentionally absent — messages encrypted with
  # Google-managed keys only.
}
