# Expected findings:
#  - SEC-AZURE-DEFENDER-001 HIGH — tier = "Free" (Defender off)

resource "azurerm_security_center_subscription_pricing" "vm" {
  tier          = "Free"
  resource_type = "VirtualMachines"
}
