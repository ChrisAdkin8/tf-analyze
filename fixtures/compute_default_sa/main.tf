# Expected findings:
#  - SEC-GCP-COMPUTE-SA-001 HIGH — compute instance uses default Compute SA

resource "google_compute_instance" "app" {
  name         = "app"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }
  # service_account intentionally omitted — should fire SEC-GCP-COMPUTE-SA-001
}
