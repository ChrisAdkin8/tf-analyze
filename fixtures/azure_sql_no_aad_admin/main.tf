# Expected findings:
#  - SEC-AZURE-SQL-001 HIGH — no azurerm_mssql_server_azure_ad_administrator present

resource "azurerm_mssql_server" "no_aad" {
  name                         = "no-aad-sql-server"
  resource_group_name          = "example-rg"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "H@rdP@ssw0rd!"
}
