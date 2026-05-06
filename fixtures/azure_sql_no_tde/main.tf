resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_mssql_server" "main" {
  name                         = "sql-main"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "PlaceholderP@ss1"
}

# SQL DB without an azurerm_mssql_database_transparent_data_encryption
# resource — TDE state is not explicitly managed.
resource "azurerm_mssql_database" "no_tde" {
  name      = "db-no-tde"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "Basic"
}
