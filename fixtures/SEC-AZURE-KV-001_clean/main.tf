# Auto-generated clean fixture for SEC-AZURE-KV-001.
# Azure Key Vault missing purge protection or soft delete
# This is a CORRECT configuration; SEC-AZURE-KV-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_key_vault" "example" {
  # ... other arguments ...
  purge_protection_enabled    = true
  soft_delete_retention_days  = 90
}
