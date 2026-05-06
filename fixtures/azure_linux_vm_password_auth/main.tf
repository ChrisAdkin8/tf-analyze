# Expected findings:
#   SEC-AZURE-VM-001  HIGH  disable_password_authentication missing (defaults to false)

resource "azurerm_linux_virtual_machine" "password_auth" {
  name                  = "demo-password-auth"
  resource_group_name   = "demo-rg"
  location              = "East US"
  size                  = "Standard_B1s"
  admin_username        = "azureuser"
  network_interface_ids = []

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

  # disable_password_authentication intentionally omitted — defaults to false
}
