# Auto-generated clean fixture for SEC-AZURE-PRIVATE-DNS-001.
# Azure Private DNS zone missing virtual network link
# This is a CORRECT configuration; SEC-AZURE-PRIVATE-DNS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_private_dns_zone_virtual_network_link" "example" {
  name                  = "example-link"
  resource_group_name   = azurerm_resource_group.example.name
  private_dns_zone_name = azurerm_private_dns_zone.example.name
  virtual_network_id    = azurerm_virtual_network.example.id
}
