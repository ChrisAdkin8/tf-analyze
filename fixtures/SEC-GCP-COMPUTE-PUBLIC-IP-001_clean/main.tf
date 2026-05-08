# Auto-generated clean fixture for SEC-GCP-COMPUTE-PUBLIC-IP-001.
# Compute instance has a public IP via access_config
# This is a CORRECT configuration; SEC-GCP-COMPUTE-PUBLIC-IP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface {
    network    = google_compute_network.vpc.id
    subnetwork = google_compute_subnetwork.private.id
    # No access_config block — no public IP assigned
  }
}
