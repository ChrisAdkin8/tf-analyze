# Auto-generated clean fixture for SEC-GCP-COMPUTE-DISK-001.
# GCP compute disk not encrypted with CSEK/CMEK
# This is a CORRECT configuration; SEC-GCP-COMPUTE-DISK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_disk" "example" {
  name = "example"
  type = "pd-ssd"
  zone = "us-central1-a"
  disk_encryption_key {
    kms_key_self_link = google_kms_crypto_key.disk.id
  }
}
