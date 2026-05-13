# Expected findings:
#  - STK-AZURE-VM-IMG-EOL-001 HIGH — offer = 0001-com-ubuntu-server-bionic (EOL)

resource "azurerm_linux_virtual_machine" "eol" {
  name                            = "legacy"
  resource_group_name             = "rg-main"
  location                        = "eastus"
  size                            = "Standard_D2s_v3"
  admin_username                  = "azureuser"
  disable_password_authentication = true
  network_interface_ids           = ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-main/providers/Microsoft.Network/networkInterfaces/nic"]

  boot_diagnostics {}

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-bionic"
    sku       = "18_04-lts-gen2"
    version   = "latest"
  }

  admin_ssh_key {
    username   = "azureuser"
    public_key = "ssh-ed25519 REDACTED user@host"
  }
}
