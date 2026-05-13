# Expected findings:
#  - SEC-GCP-COMPUTE-PROJSSH-001 MEDIUM — block-project-ssh-keys = FALSE

resource "google_compute_instance" "projssh" {
  name         = "shared"
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
    block-project-ssh-keys = "FALSE"
  }
}
