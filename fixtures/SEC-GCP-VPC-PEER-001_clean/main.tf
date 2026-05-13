# Auto-generated clean fixture for SEC-GCP-VPC-PEER-001.
# GCP VPC peering exports all custom routes (broad blast radius)
# This is a CORRECT configuration; SEC-GCP-VPC-PEER-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_network_peering" "example" {
  name                 = "to-other"
  network              = google_compute_network.main.id
  peer_network         = "projects/other/global/networks/main"
  export_custom_routes = false
  import_custom_routes = false
}
