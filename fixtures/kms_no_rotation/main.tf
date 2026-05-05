# Expected findings:
#  - STK-KMS-001 HIGH — symmetric key missing rotation_period

resource "google_kms_key_ring" "primary" {
  name     = "primary"
  location = "us-central1"
}

resource "google_kms_crypto_key" "data" {
  name     = "data"
  key_ring = google_kms_key_ring.primary.id
  purpose  = "ENCRYPT_DECRYPT"
  # rotation_period intentionally omitted

  lifecycle {
    prevent_destroy = true
  }
}
