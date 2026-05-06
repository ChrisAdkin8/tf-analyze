resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_container_registry" "admin_on" {
  name                = "acradminon1234"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Standard"
  admin_enabled       = true
  # admin account shares credentials with every consumer — cannot be audited
  # per-user or scoped to specific repositories.
}
