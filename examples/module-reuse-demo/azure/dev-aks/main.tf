# Smaller dev AKS — cluster + extra node pool + UAMI only. Three of the
# nine supporting types present (threshold = 2), so Module Reuse Advisor
# fires MOD-REUSE-AZURE-AKS-001 at medium confidence.
#
# Demonstrates the confidence ladder: prod-aks/ has 6 supporting types
# (high confidence), dev-aks/ has 3 (medium), and the rule is conservative
# enough that an even smaller cluster would not fire at all.

resource "azurerm_kubernetes_cluster" "dev" {
  name                = "dev-aks"
  location            = "eastus"
  resource_group_name = "dev-rg"
  dns_prefix          = "devaks"

  default_node_pool {
    name       = "system"
    node_count = 1
    vm_size    = "Standard_D2s_v5"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "spot" {
  name                  = "spot"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.dev.id
  vm_size               = "Standard_D4s_v5"
  node_count            = 1
  priority              = "Spot"
  eviction_policy       = "Delete"
}

resource "azurerm_user_assigned_identity" "dev_kubelet" {
  name                = "dev-aks-kubelet"
  location            = "eastus"
  resource_group_name = "dev-rg"
}
