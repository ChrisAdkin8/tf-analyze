# Auto-generated clean fixture for STK-AZURE-SQL-001.
# Azure MySQL/PostgreSQL single server is deprecated
# This is a CORRECT configuration; STK-AZURE-SQL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mysql_flexible_server" "example" {
  name                   = "example"
  resource_group_name    = azurerm_resource_group.example.name
  location               = azurerm_resource_group.example.location
  administrator_login    = "adminuser"
  administrator_password = var.db_password
  sku_name               = "GP_Standard_D2ds_v4"
  version                = "8.0.21"
}
