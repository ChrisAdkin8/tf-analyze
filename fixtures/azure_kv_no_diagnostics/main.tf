# Expected findings:
#  - SEC-AZURE-LOGGING-001 HIGH — azurerm_key_vault with no azurerm_monitor_diagnostic_setting

resource "azurerm_key_vault" "no_diag" {
  name                = "no-diag-kv"
  location            = "eastus"
  resource_group_name = "example-rg"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}
