# Auto-generated clean fixture for STK-AZURE-SEARCH-001.
# Azure Cognitive Search service missing identity (no CMK)
# This is a CORRECT configuration; STK-AZURE-SEARCH-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_search_service" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "standard"
  identity { type = "SystemAssigned" }
}
