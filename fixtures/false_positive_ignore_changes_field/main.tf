# Expected findings: NONE
# Guards against: ROB-DRIFT-001
#
# ROB-DRIFT-001 flags `ignore_changes = all`. It must NOT fire when:
#  - the literal string "ignore_changes = all" appears in a comment
#  - a field named `all` (not the magic keyword) appears in ignore_changes
#  - the string "ignore_changes = all" appears inside a heredoc/string

resource "google_storage_bucket" "ok" {
  name     = "ok"
  location = "US"

  # Workaround documented here: ignore_changes = all (historical incident)
  lifecycle {
    ignore_changes = [labels]
  }
}

resource "google_compute_instance" "ok" {
  name         = "ok"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  description  = "do not set ignore_changes = all on this"

  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }

  lifecycle {
    ignore_changes = [metadata, labels]
  }
}
