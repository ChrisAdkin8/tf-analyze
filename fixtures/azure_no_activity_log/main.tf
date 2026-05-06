# Expected findings: SEC-AZURE-MONITOR-001
# (azurerm_resource_group present but no azurerm_subscription_diagnostic_setting)

resource "azurerm_resource_group" "main" {
  name     = "rg-demo"
  location = "eastus"
  # No azurerm_subscription_diagnostic_setting companion resource
}
