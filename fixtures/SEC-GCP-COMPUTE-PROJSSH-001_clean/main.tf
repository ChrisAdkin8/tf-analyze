# Auto-generated clean fixture for SEC-GCP-COMPUTE-PROJSSH-001.
# GCP Compute instance permits project-wide SSH keys
# This is a CORRECT configuration; SEC-GCP-COMPUTE-PROJSSH-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk { initialize_params { image = "debian-cloud/debian-12" } }
  network_interface { network = "default" }
  metadata = {
    block-project-ssh-keys = "TRUE"
  }
}
