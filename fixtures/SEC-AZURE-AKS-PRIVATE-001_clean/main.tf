# Auto-generated clean fixture for SEC-AZURE-AKS-PRIVATE-001.
# Azure AKS cluster API server publicly accessible (not a private cluster)
# This is a CORRECT configuration; SEC-AZURE-AKS-PRIVATE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_kubernetes_cluster" "example" {
  name                    = "example"
  location                = azurerm_resource_group.example.location
  resource_group_name     = azurerm_resource_group.example.name
  dns_prefix              = "example"
  private_cluster_enabled = true
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2s_v3"
  }
  identity { type = "SystemAssigned" }
}
