# Expected findings:
#  - ROB-DRIFT-001 HIGH — ignore_changes = all masks all drift

resource "google_compute_instance" "unmanaged" {
  name         = "legacy-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  lifecycle {
    ignore_changes = all
  }
}

# Explicit ignore list — OK, no finding
resource "google_compute_instance" "managed" {
  name         = "managed-vm"
  machine_type = "e2-micro"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  lifecycle {
    ignore_changes = [metadata]
  }
}
