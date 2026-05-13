# Expected findings:
#  - SEC-AZURE-VNET-ENC-001 LOW — no encryption block

resource "azurerm_virtual_network" "no_enc" {
  name                = "vnet-sensitive"
  location            = "eastus"
  resource_group_name = "rg-main"
  address_space       = ["10.1.0.0/16"]

  ddos_protection_plan {
    id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Network/ddosProtectionPlans/plan"
    enable = true
  }
}
