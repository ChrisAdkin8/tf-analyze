# Expected findings:
#  - ROB-AZURE-SQL-001 MEDIUM — no short_term_retention_policy block

resource "azurerm_mssql_server" "example" {
  name                         = "example-sql-server"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "H@rdP@ssw0rd!"
}

resource "azurerm_mssql_database" "no_backup" {
  name      = "example-db"
  server_id = azurerm_mssql_server.example.id
  sku_name  = "S0"
}
