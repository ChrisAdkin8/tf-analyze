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

# Expected findings:
#  - STK-AZURE-SQL-TDE-001 HIGH — TDE explicitly turned off
resource "azurerm_mssql_database" "no_tde" {
  name                                = "db-no-tde"
  server_id                           = azurerm_mssql_server.main.id
  sku_name                            = "DW100c"
  transparent_data_encryption_enabled = false
}
