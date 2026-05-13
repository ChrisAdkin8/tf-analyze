# Expected findings:
#  - STK-AZURE-LB-001 MEDIUM — no diagnostic_setting bound

resource "azurerm_lb" "main" {
  name                = "lb-main"
  location            = "eastus"
  resource_group_name = "rg-main"
  sku                 = "Standard"

  frontend_ip_configuration {
    name                 = "public"
    public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Network/publicIPAddresses/lb-pip"
  }
}
