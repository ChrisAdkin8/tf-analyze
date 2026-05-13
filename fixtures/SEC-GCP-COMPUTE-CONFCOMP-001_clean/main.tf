# Auto-generated clean fixture for SEC-GCP-COMPUTE-CONFCOMP-001.
# GCP Compute instance not using Confidential Computing (TDX/SEV)
# This is a CORRECT configuration; SEC-GCP-COMPUTE-CONFCOMP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "n2d-standard-2"
  zone         = "us-central1-a"
  boot_disk { initialize_params { image = "debian-cloud/debian-12" } }
  network_interface { network = "default" }
  confidential_instance_config {
    enable_confidential_compute = true
  }
  scheduling { on_host_maintenance = "TERMINATE" }
}
