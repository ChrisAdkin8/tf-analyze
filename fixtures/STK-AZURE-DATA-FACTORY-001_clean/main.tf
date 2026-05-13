# Auto-generated clean fixture for STK-AZURE-DATA-FACTORY-001.
# Azure Data Factory not using managed virtual network
# This is a CORRECT configuration; STK-AZURE-DATA-FACTORY-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_data_factory" "example" {
  name                            = "example"
  resource_group_name             = azurerm_resource_group.example.name
  location                        = azurerm_resource_group.example.location
  managed_virtual_network_enabled = true
  public_network_enabled          = false
}
