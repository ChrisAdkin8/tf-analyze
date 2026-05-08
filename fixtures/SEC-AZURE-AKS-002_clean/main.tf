# Auto-generated clean fixture for SEC-AZURE-AKS-002.
# AKS cluster missing network policy
# This is a CORRECT configuration; SEC-AZURE-AKS-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
  identity { type = "SystemAssigned" }
}
