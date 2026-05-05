# Compute section — exercises SEC-COMPUTE-SA-001 and
# SEC-COMPUTE-PUBLIC-IP-001.

# SEC-COMPUTE-SA-001 HIGH (no service_account block — defaults to
# project's default Compute SA which has roles/editor).
# SEC-COMPUTE-PUBLIC-IP-001 HIGH (access_config block requests a
# public IP).
resource "google_compute_instance" "exposed" {
  name         = "demo-exposed"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
    access_config {
      # ephemeral public IP
    }
  }
  # service_account intentionally omitted
}

# SEC-NETWORK-001 CRITICAL — SSH open to the world.
resource "google_compute_firewall" "ssh_open" {
  name      = "demo-ssh-open"
  network   = "default"
  direction = "INGRESS"

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
