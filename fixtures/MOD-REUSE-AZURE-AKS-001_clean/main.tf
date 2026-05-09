# Clean fixture for MOD-REUSE-AZURE-AKS-001.
#
# A bare AKS cluster with no extra node pool, identity, or diagnostics —
# supporting-types threshold (2) is not met, so the fingerprint must
# NOT fire.

resource "azurerm_kubernetes_cluster" "minimal" {
  name                = "minimal-aks"
  location            = "eastus"
  resource_group_name = "demo-rg"
  dns_prefix          = "minaks"

  default_node_pool {
    name       = "system"
    node_count = 1
    vm_size    = "Standard_D2s_v5"
  }

  identity {
    type = "SystemAssigned"
  }
}
