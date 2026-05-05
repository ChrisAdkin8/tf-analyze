# Expected findings:
#  - ROB-COUNTREF-002 HIGH — indexed reference to resource with count=length(...) is not guarded

variable "subnets" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

resource "google_compute_subnetwork" "subnet" {
  count         = length(var.subnets)
  name          = "subnet-${count.index}"
  ip_cidr_range = var.subnets[count.index]
  region        = "us-central1"
  network       = "default"
}

resource "google_compute_instance" "app" {
  name         = "app"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  network_interface {
    subnetwork = google_compute_subnetwork.subnet[0].self_link
  }
  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }
}
