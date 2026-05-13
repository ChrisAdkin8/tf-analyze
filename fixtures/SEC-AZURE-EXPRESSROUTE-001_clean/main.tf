# Auto-generated clean fixture for SEC-AZURE-EXPRESSROUTE-001.
# Azure ExpressRoute port missing MACsec encryption
# This is a CORRECT configuration; SEC-AZURE-EXPRESSROUTE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_express_route_port" "example" {
  name                = "er-port"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  peering_location    = "Equinix-Washington-DC-DC2"
  bandwidth_in_gbps   = 10
  encapsulation       = "Dot1Q"
  macsec_cipher       = "GcmAes128"
}
