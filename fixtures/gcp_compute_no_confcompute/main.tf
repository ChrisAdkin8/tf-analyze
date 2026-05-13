# Expected findings:
#  - SEC-GCP-COMPUTE-CONFCOMP-001 LOW — no confidential_instance_config

resource "google_compute_instance" "regular" {
  name         = "regular"
  machine_type = "n2d-standard-2"
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
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
  }
}
