# Expected findings:
#  - SEC-GCP-VPC-PEER-001 MEDIUM — export_custom_routes = true

resource "google_compute_network_peering" "broad" {
  name                 = "to-shared"
  network              = "projects/example/global/networks/main"
  peer_network         = "projects/shared/global/networks/main"
  export_custom_routes = true
}
