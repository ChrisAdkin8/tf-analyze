# Expected findings:
#  - STK-GCP-KMS-LOCATION-001 HIGH — bucket in us-central1 references key ring in us-east1

resource "google_kms_key_ring" "primary" {
  name     = "primary"
  location = "us-east1"
}

resource "google_kms_crypto_key" "primary" {
  name     = "primary"
  key_ring = google_kms_key_ring.primary.id
}

resource "google_storage_bucket" "data" {
  name                        = "data"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.primary.id
  }

  lifecycle {
    prevent_destroy = true
  }
}
