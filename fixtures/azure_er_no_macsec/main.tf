# Expected findings:
#  - SEC-AZURE-EXPRESSROUTE-001 MEDIUM — no macsec_cipher

resource "azurerm_express_route_port" "no_macsec" {
  name                = "er-port"
  resource_group_name = "rg-main"
  location            = "eastus"
  peering_location    = "Equinix-Washington-DC-DC2"
  bandwidth_in_gbps   = 10
  encapsulation       = "Dot1Q"
}
