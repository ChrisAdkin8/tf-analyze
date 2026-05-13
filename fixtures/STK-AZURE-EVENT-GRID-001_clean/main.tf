# Auto-generated clean fixture for STK-AZURE-EVENT-GRID-001.
# Azure Event Grid topic missing managed identity and CMK
# This is a CORRECT configuration; STK-AZURE-EVENT-GRID-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_eventgrid_topic" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  identity { type = "SystemAssigned" }
}
