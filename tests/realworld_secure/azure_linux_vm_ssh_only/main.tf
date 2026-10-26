resource "azurerm_linux_virtual_machine" "app" {
  name                  = "app-vm"
  resource_group_name   = "rg-app"
  location              = "uksouth"
  size                  = "Standard_B2s"
  admin_username        = "azureuser"
  network_interface_ids = [var.nic_id]

  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}

variable "nic_id" {
  type        = string
  description = "NIC ID."
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key."
}
