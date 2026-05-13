# Auto-generated clean fixture for SEC-AZURE-ACR-002.
# Azure Container Registry missing image retention policy
# This is a CORRECT configuration; SEC-AZURE-ACR-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_container_registry" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Premium"
  retention_policy {
    days    = 30
    enabled = true
  }
}
