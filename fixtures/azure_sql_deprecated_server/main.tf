resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

# azurerm_mysql_server is the deprecated Single Server SKU —
# Microsoft ended support September 16, 2024.
resource "azurerm_mysql_server" "deprecated" {
  name                = "mysql-deprecated"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  administrator_login          = "mysqladmin"
  administrator_login_password = "PlaceholderP@ss1"
  sku_name            = "B_Gen5_1"
  storage_mb          = 5120
  version             = "5.7"
  ssl_enforcement_enabled = true
}
