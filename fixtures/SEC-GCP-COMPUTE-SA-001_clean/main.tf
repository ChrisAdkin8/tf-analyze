# Auto-generated clean fixture for SEC-GCP-COMPUTE-SA-001.
# Compute instance uses default Compute Engine service account
# This is a CORRECT configuration; SEC-GCP-COMPUTE-SA-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_service_account" "vm" {
  account_id = "vm-runtime"
}
resource "google_compute_instance" "example" {
  name         = "example"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  boot_disk {
    initialize_params { image = "debian-cloud/debian-11" }
  }
  network_interface { network = "default" }
  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }
}
