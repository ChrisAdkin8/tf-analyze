# GCP Shared VPC host project network. Has the same resource shape as
# `prod-network/` — VPC + 3 subnets + 2 firewalls + router + NAT —
# BUT also declares a `google_compute_shared_vpc_host_project` and a
# `google_compute_shared_vpc_service_project`.
#
# Both of those are in MOD-REUSE-GCP-NETWORK-001's `exclusions:` list
# (they signal "we're using the GCP Shared-VPC pattern; the community
# network module doesn't model that"). The Module Reuse Advisor MUST
# NOT fire here, even though the resource cluster otherwise matches.
#
# Negative case: demonstrates the exclusion mechanism is doing real
# work. The same resources without the shared-VPC declarations would
# fire the rule.

resource "google_compute_shared_vpc_host_project" "host" {
  project = "shared-vpc-host"
}

resource "google_compute_shared_vpc_service_project" "service" {
  host_project    = google_compute_shared_vpc_host_project.host.project
  service_project = "shared-vpc-svc"
}

resource "google_compute_network" "shared_vpc" {
  name                    = "shared-vpc"
  auto_create_subnetworks = false
  project                 = google_compute_shared_vpc_host_project.host.project
}

resource "google_compute_subnetwork" "shared_app" {
  name          = "shared-app"
  ip_cidr_range = "10.30.10.0/24"
  region        = "us-central1"
  network       = google_compute_network.shared_vpc.id
  project       = google_compute_shared_vpc_host_project.host.project
}

resource "google_compute_subnetwork" "shared_data" {
  name          = "shared-data"
  ip_cidr_range = "10.30.20.0/24"
  region        = "us-central1"
  network       = google_compute_network.shared_vpc.id
  project       = google_compute_shared_vpc_host_project.host.project
}

resource "google_compute_firewall" "shared_internal" {
  name    = "shared-internal"
  network = google_compute_network.shared_vpc.name
  project = google_compute_shared_vpc_host_project.host.project

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["10.30.0.0/16"]
}

resource "google_compute_router" "shared_egress" {
  name    = "shared-egress-router"
  region  = "us-central1"
  network = google_compute_network.shared_vpc.id
  project = google_compute_shared_vpc_host_project.host.project
}
