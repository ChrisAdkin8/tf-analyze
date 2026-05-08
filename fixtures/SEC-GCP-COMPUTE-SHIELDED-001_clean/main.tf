# Auto-generated clean fixture for SEC-GCP-COMPUTE-SHIELDED-001.
# GCP Compute instance missing shielded instance configuration
# This is a CORRECT configuration; SEC-GCP-COMPUTE-SHIELDED-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface { network = "default" }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
