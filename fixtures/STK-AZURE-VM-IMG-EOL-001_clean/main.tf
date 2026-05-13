# Auto-generated clean fixture for STK-AZURE-VM-IMG-EOL-001.
# Azure virtual machine using end-of-life OS image
# This is a CORRECT configuration; STK-AZURE-VM-IMG-EOL-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_virtual_machine" "example" {
  name                  = "example"
  resource_group_name   = azurerm_resource_group.example.name
  location              = azurerm_resource_group.example.location
  size                  = "Standard_D2s_v3"
  admin_username        = "azureuser"
  network_interface_ids = [azurerm_network_interface.example.id]
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
  os_disk { caching = "ReadWrite" storage_account_type = "Standard_LRS" }
}
