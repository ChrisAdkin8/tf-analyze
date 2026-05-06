# Expected findings:
#  - SEC-AZURE-KV-001 HIGH — purge_protection_enabled = false

resource "azurerm_key_vault" "insecure" {
  name                = "insecure-kv"
  location            = "eastus"
  resource_group_name = "example-rg"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"

  purge_protection_enabled   = false
  soft_delete_retention_days = 7
}
