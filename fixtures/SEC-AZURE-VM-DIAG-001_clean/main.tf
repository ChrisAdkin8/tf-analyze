# Auto-generated clean fixture for SEC-AZURE-VM-DIAG-001.
# Azure virtual machine missing boot diagnostics
# This is a CORRECT configuration; SEC-AZURE-VM-DIAG-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_virtual_machine" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D2s_v3"
  admin_username      = "azureuser"
  network_interface_ids = [azurerm_network_interface.example.id]
  boot_diagnostics {}
  os_disk { caching = "ReadWrite" storage_account_type = "Standard_LRS" }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
