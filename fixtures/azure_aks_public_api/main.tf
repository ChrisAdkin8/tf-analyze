# Expected findings:
#  - SEC-AZURE-AKS-PRIVATE-001 HIGH — no private_cluster_enabled

resource "azurerm_kubernetes_cluster" "public" {
  name                = "public-cluster"
  location            = "eastus"
  resource_group_name = "rg-main"
  dns_prefix          = "app"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2s_v3"
  }

  identity {
    type = "SystemAssigned"
  }
}
