# Auto-generated clean fixture for SEC-AZURE-ACR-001.
# Azure Container Registry admin account enabled
# This is a CORRECT configuration; SEC-AZURE-ACR-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_container_registry" "example" {
  name                = "exampleacr"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard"
  admin_enabled       = false
}
