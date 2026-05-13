# Expected findings:
#  - SEC-AZURE-KV-CERT-001 MEDIUM — no certificate_policy

resource "azurerm_key_vault_certificate" "no_policy" {
  name         = "tls-cert"
  key_vault_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.KeyVault/vaults/kv-main"

  certificate {
    contents = "REDACTED"
    password = "REDACTED"
  }
}
