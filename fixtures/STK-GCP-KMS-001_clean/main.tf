# Auto-generated clean fixture for STK-GCP-KMS-001.
# KMS crypto key missing rotation period
# This is a CORRECT configuration; STK-GCP-KMS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_kms_crypto_key" "example" {
  name            = "example"
  key_ring        = google_kms_key_ring.example.id
  rotation_period = "7776000s"
  lifecycle {
    prevent_destroy = true
  }
}
