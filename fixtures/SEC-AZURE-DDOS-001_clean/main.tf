# Auto-generated clean fixture for SEC-AZURE-DDOS-001.
# Azure Virtual Network missing DDoS protection plan
# This is a CORRECT configuration; SEC-AZURE-DDOS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_virtual_network" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  address_space       = ["10.0.0.0/16"]
  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.example.id
    enable = true
  }
}
