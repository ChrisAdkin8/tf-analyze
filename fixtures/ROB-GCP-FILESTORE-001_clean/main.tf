# Auto-generated clean fixture for ROB-GCP-FILESTORE-001.
# GCP Filestore instance missing backup configuration
# This is a CORRECT configuration; ROB-GCP-FILESTORE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_filestore_backup" "example" {
  name        = "weekly"
  location    = "us-central1"
  source_instance = google_filestore_instance.example.id
  source_file_share = "share1"
}
