# Expected findings:
#  - SEC-GCP-COMPUTE-OSLOGIN-001 MEDIUM — enable-oslogin = FALSE

resource "google_compute_instance" "oslogin_off" {
  name         = "legacy"
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
  metadata = {
    enable-oslogin = "FALSE"
  }
}
