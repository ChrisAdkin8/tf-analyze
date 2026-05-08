# Auto-generated clean fixture for STK-AZURE-DB-001.
# Azure MySQL/PostgreSQL server missing SSL enforcement
# This is a CORRECT configuration; STK-AZURE-DB-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_mysql_server" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku_name            = "B_Gen5_1"
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
