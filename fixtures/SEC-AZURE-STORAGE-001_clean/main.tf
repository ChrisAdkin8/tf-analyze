# Auto-generated clean fixture for SEC-AZURE-STORAGE-001.
# Azure storage account allows non-HTTPS traffic
# This is a CORRECT configuration; SEC-AZURE-STORAGE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  https_traffic_only_enabled = true
  min_tls_version            = "TLS1_2"
}
