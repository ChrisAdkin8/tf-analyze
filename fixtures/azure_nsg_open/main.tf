# Expected findings:
#  - STK-AZURE-NSG-001 HIGH (escalates to CRITICAL) — source_address_prefix = "*" with SSH port 22

resource "azurerm_network_security_rule" "ssh_open" {
  name                        = "allow-ssh-internet"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "example-rg"
  network_security_group_name = "example-nsg"
}
