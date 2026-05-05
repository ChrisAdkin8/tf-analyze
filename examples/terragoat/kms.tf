# KMS section — exercises STK-KMS-001 and STK-KMS-LOCATION-001.

# Two key rings in different locations to set up the location-mismatch
# scenario for the storage bucket below.
resource "google_kms_key_ring" "us_east" {
  name     = "primary"
  location = "us-east1"
}

# STK-KMS-001 HIGH — symmetric key with no rotation_period.
resource "google_kms_crypto_key" "primary" {
  name     = "primary"
  key_ring = google_kms_key_ring.us_east.id
  purpose  = "ENCRYPT_DECRYPT"
  # rotation_period intentionally omitted

  lifecycle {
    prevent_destroy = true
  }
}

# STK-KMS-LOCATION-001 HIGH — bucket in us-central1 references key ring
# in us-east1 (cross-region encrypt/decrypt).
resource "google_storage_bucket" "encrypted" {
  name                        = "demo-encrypted"
  location                    = "us-central1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  encryption {
    default_kms_key_name = google_kms_crypto_key.primary.id
  }

  versioning {
    enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }
}
