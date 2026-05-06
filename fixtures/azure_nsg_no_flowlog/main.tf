resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

# NSG present but no azurerm_network_watcher_flow_log in this repo
resource "azurerm_network_security_group" "main" {
  name                = "nsg-app"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}
