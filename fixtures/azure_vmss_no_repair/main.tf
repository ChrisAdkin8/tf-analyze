# Expected findings:
#  - ROB-AZURE-VMSS-001 MEDIUM — no automatic_instance_repair

resource "azurerm_linux_virtual_machine_scale_set" "no_repair" {
  name                            = "app"
  resource_group_name             = "rg-main"
  location                        = "eastus"
  sku                             = "Standard_D2s_v3"
  instances                       = 3
  admin_username                  = "azureuser"
  disable_password_authentication = true

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  network_interface {
    name    = "ni"
    primary = true
    ip_configuration {
      name      = "ic"
      primary   = true
      subnet_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app"
    }
  }

  admin_ssh_key {
    username   = "azureuser"
    public_key = "ssh-ed25519 REDACTED user@host"
  }
}
