# Expected findings:
#  - SEC-AZURE-SQL-VULN-001 HIGH — no vulnerability_assessment bound

resource "azurerm_mssql_server" "main" {
  name                         = "sql-app2"
  resource_group_name          = "rg-main"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "REDACTED"
  minimum_tls_version          = "1.2"

  azuread_administrator {
    login_username = "admins@example.com"
    object_id      = "00000000-0000-0000-0000-000000000000"
  }
}
