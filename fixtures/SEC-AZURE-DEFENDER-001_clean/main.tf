# Auto-generated clean fixture for SEC-AZURE-DEFENDER-001.
# Microsoft Defender for Cloud not enabled on subscription
# This is a CORRECT configuration; SEC-AZURE-DEFENDER-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_security_center_subscription_pricing" "vm" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}
