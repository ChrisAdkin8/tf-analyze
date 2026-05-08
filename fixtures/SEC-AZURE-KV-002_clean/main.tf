# Auto-generated clean fixture for SEC-AZURE-KV-002.
# Key Vault missing network ACL deny-by-default
# This is a CORRECT configuration; SEC-AZURE-KV-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_key_vault" "example" {
  # ... other arguments ...
  network_acls {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = []
  }
}
