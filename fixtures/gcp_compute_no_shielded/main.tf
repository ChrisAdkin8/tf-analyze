# Expected findings: SEC-GCP-COMPUTE-SHIELDED-001

resource "google_compute_instance" "app" {
  name         = "demo-app"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
  }

  # No shielded_instance_config block
}
