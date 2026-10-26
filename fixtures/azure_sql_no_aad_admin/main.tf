# Expected findings:
#  - SEC-AZURE-SQL-001 HIGH — azurerm_mssql_server without an azuread_administrator block

resource "azurerm_mssql_server" "no_aad" {
  name                         = "no-aad-sql-server"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "H@rdP@ssw0rd!"
}
