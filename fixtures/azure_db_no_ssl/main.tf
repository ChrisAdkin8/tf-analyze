resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_mysql_server" "no_ssl" {
  name                = "mysql-no-ssl"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  administrator_login          = "mysqladmin"
  administrator_login_password = "PlaceholderP@ss1"
  sku_name            = "B_Gen5_1"
  storage_mb          = 5120
  version             = "8.0"
  ssl_enforcement_enabled = false  # plaintext connections accepted
}
