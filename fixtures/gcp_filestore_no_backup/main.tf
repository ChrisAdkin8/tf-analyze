# Expected findings:
#  - ROB-GCP-FILESTORE-001 MEDIUM — no google_filestore_backup declared

resource "google_filestore_instance" "share" {
  name     = "share"
  location = "us-central1-a"
  tier     = "BASIC_HDD"
  file_shares {
    capacity_gb = 1024
    name        = "share1"
  }
  networks {
    network = "default"
    modes   = ["MODE_IPV4"]
  }
}
