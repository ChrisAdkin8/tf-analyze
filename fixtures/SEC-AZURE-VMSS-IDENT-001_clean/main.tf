# Auto-generated clean fixture for SEC-AZURE-VMSS-IDENT-001.
# Azure VM Scale Set has no managed identity
# This is a CORRECT configuration; SEC-AZURE-VMSS-IDENT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_virtual_machine_scale_set" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  sku                 = "Standard_D2s_v3"
  instances           = 3
  admin_username      = "azureuser"
  identity { type = "SystemAssigned" }
  os_disk { caching = "ReadWrite" storage_account_type = "Standard_LRS" }
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
      subnet_id = azurerm_subnet.example.id
    }
  }
}
