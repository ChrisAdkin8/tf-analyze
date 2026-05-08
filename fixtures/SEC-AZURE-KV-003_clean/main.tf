# Auto-generated clean fixture for SEC-AZURE-KV-003.
# Azure Key Vault key missing rotation policy
# This is a CORRECT configuration; SEC-AZURE-KV-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_key_vault_key" "example" {
  name         = "example"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "verify"]
  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P90D"
    notify_before_expiry = "P29D"
  }
}
