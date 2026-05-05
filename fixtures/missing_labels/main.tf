# Expected findings:
#  - OPS-LABELS-001 MEDIUM — compute instance missing labels
#  - OPS-LABELS-001 MEDIUM — storage bucket missing labels

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

resource "google_compute_instance" "web" {
  name         = "web-server"
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
}

resource "google_storage_bucket" "data" {
  name     = "${var.project_id}-data"
  location = "US"
}

resource "google_compute_instance" "labeled" {
  name         = "labeled-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  labels = {
    environment = "dev"
    managed_by  = "terraform"
  }

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
  }
}
