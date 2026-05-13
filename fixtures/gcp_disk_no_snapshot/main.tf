# Expected findings:
#  - ROB-GCP-DISK-SNAP-001 MEDIUM — no resource_policies

resource "google_compute_disk" "data" {
  name = "data"
  type = "pd-ssd"
  size = 100
  zone = "us-central1-a"
  disk_encryption_key {
    kms_key_self_link = "projects/example/locations/us-central1/keyRings/r/cryptoKeys/k"
  }
}
