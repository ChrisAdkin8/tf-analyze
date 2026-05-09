# Clean fixture for MOD-REUSE-GCP-NETWORK-001.
#
# A network plus two subnetworks but nothing else — supporting-types
# threshold (2) is not met, so the fingerprint must NOT fire.

resource "google_compute_network" "minimal" {
  name                    = "minimal"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "minimal_a" {
  name          = "minimal-a"
  ip_cidr_range = "192.168.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.minimal.id
}

resource "google_compute_subnetwork" "minimal_b" {
  name          = "minimal-b"
  ip_cidr_range = "192.168.2.0/24"
  region        = "us-central1"
  network       = google_compute_network.minimal.id
}
