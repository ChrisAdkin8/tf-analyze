# Auto-generated clean fixture for SEC-AZURE-VM-001.
# Linux VM allows SSH password authentication
# This is a CORRECT configuration; SEC-AZURE-VM-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_virtual_machine" "example" {
  # ... other arguments ...
  disable_password_authentication = true
  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
}
