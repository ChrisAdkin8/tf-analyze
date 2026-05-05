# Expected findings:
#  - SEC-COMPUTE-PUBLIC-IP-001 HIGH — VM has access_config block (public IP)

resource "google_service_account" "vm" {
  account_id = "vm-runtime"
}

resource "google_compute_instance" "app" {
  name         = "app"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }

  network_interface {
    network = "default"
    access_config {
      # ephemeral public IP — should fire SEC-COMPUTE-PUBLIC-IP-001
    }
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }
}
