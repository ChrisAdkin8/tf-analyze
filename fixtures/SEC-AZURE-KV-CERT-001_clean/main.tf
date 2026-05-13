# Auto-generated clean fixture for SEC-AZURE-KV-CERT-001.
# Azure Key Vault certificate missing auto-renewal policy
# This is a CORRECT configuration; SEC-AZURE-KV-CERT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_key_vault_certificate" "example" {
  name         = "example"
  key_vault_id = azurerm_key_vault.example.id
  certificate_policy {
    issuer_parameters { name = "Self" }
    key_properties {
      exportable = false
      key_type   = "RSA"
      key_size   = 2048
      reuse_key  = false
    }
    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      trigger {
        days_before_expiry = 30
      }
    }
    secret_properties { content_type = "application/x-pkcs12" }
  }
}
