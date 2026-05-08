# Expected findings:
#  - SEC-GCP-COMPUTE-DISK-001 MEDIUM — no disk_encryption_key

resource "google_compute_disk" "data" {
  name    = "data"
  type    = "pd-ssd"
  zone    = "us-central1-a"
  size    = 100
  # No disk_encryption_key block
}
