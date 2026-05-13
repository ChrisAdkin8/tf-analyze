# Auto-generated clean fixture for SEC-AZURE-BASTION-001.
# Azure Bastion host using Basic SKU (no shareable links, no RBAC)
# This is a CORRECT configuration; SEC-AZURE-BASTION-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_bastion_host" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
  scale_units         = 2
  ip_configuration {
    name                 = "config"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }
}
