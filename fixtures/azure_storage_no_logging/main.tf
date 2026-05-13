# Expected findings:
#  - SEC-AZURE-STORAGE-004 MEDIUM — no queue_properties block (diagnostic logging missing)

resource "azurerm_storage_account" "no_logging" {
  name                     = "nologgingstorage"
  resource_group_name      = "rg-main"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  https_only               = true
  min_tls_version          = "TLS1_2"
  # No queue_properties.logging, no diagnostic setting.
}
