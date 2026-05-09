# Hand-rolled GCP production VPC + subnets + Cloud Router + Cloud NAT
# + firewall — matches the shape of `terraform-google-modules/network/google`.
#
# Module Reuse Advisor will fire MOD-REUSE-GCP-NETWORK-001.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "demo-project"
  region  = "us-central1"
}

resource "google_compute_network" "vpc" {
  name                    = "prod-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "app" {
  name          = "app"
  ip_cidr_range = "10.10.10.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id

  private_ip_google_access = true
}

resource "google_compute_subnetwork" "data" {
  name          = "data"
  ip_cidr_range = "10.10.20.0/24"
  region        = "us-central1"
  network       = google_compute_network.vpc.id

  private_ip_google_access = true
}

resource "google_compute_subnetwork" "gke_pods" {
  name          = "gke-pods"
  ip_cidr_range = "10.20.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.vpc.id
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.10.0.0/16", "10.20.0.0/16"]
}

resource "google_compute_firewall" "allow_iap" {
  name    = "allow-iap-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Google IAP forwarder range — gives engineers a tunnel without
  # opening 0.0.0.0/0.
  source_ranges = ["35.235.240.0/20"]
}

resource "google_compute_router" "egress" {
  name    = "egress-router"
  region  = "us-central1"
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "egress" {
  name                               = "egress-nat"
  router                             = google_compute_router.egress.name
  region                             = google_compute_router.egress.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}
