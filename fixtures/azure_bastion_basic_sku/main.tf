# Expected findings:
#  - SEC-AZURE-BASTION-001 LOW — sku = Basic

resource "azurerm_bastion_host" "basic" {
  name                = "bastion"
  location            = "eastus"
  resource_group_name = "rg-main"
  sku                 = "Basic"

  ip_configuration {
    name                 = "ipc"
    subnet_id            = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Network/virtualNetworks/vnet/subnets/AzureBastionSubnet"
    public_ip_address_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Network/publicIPAddresses/bastion-pip"
  }
}
