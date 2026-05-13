# Expected findings:
#  - STK-AZURE-MYSQL-EOL-001 HIGH — version = 5.7 (EOL)

resource "azurerm_mysql_flexible_server" "legacy" {
  name                   = "legacy-mysql"
  resource_group_name    = "rg-main"
  location               = "eastus"
  version                = "5.7"
  sku_name               = "GP_Standard_D2ds_v4"
  administrator_login    = "mysqladmin"
  administrator_password = "REDACTED"
  storage {
    size_gb = 32
  }
}
