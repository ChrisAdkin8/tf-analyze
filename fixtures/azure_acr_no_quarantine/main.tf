# Expected findings:
#  - SEC-AZURE-ACR-003 MEDIUM — no quarantine_policy_enabled

resource "azurerm_container_registry" "no_quarantine" {
  name                = "noquarantineacr"
  resource_group_name = "rg-main"
  location            = "eastus"
  sku                 = "Premium"
  admin_enabled       = false

  retention_policy {
    days    = 30
    enabled = true
  }
  # No quarantine_policy_enabled -- unscanned images pullable on push.
}
