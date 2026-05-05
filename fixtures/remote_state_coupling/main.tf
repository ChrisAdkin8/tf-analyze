# Expected findings:
#  - ROB-REMOTESTATE-001 MEDIUM — terraform_remote_state couples modules implicitly

data "terraform_remote_state" "network" {
  backend = "gcs"
  config = {
    bucket = "tf-state-prod"
    prefix = "network"
  }
}

resource "google_compute_instance" "app" {
  name         = "app"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  network_interface {
    network = data.terraform_remote_state.network.outputs.vpc_self_link
  }
  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }
}
