# Auto-generated clean fixture for STK-AZURE-MYSQL-EOL-001.
# Azure MySQL/PostgreSQL flexible server on end-of-life version
# This is a CORRECT configuration; STK-AZURE-MYSQL-EOL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_postgresql_flexible_server" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  version             = "16"
  sku_name            = "GP_Standard_D2s_v3"
  storage_mb          = 32768
  administrator_login    = "pgadmin"
  administrator_password = "REDACTED"
}
