resource "azurerm_resource_group" "example" {
  name     = "example-rg"
  location = "East US"
}

resource "azurerm_mssql_server" "example" {
  name                         = "example-sqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_password
}

resource "azurerm_mssql_database" "example" {
  name      = "example-db"
  server_id = azurerm_mssql_server.example.id
  sku_name  = "Basic"
}

resource "azurerm_mssql_database_transparent_data_encryption" "example" {
  database_id = azurerm_mssql_database.example.id
  state       = "Enabled"
}
