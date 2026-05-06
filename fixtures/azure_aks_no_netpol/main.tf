resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

# AKS cluster with no network_profile.network_policy — all pod-to-pod
# traffic is permitted by default.
resource "azurerm_kubernetes_cluster" "no_netpol" {
  name                = "aks-no-netpol"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  dns_prefix          = "aks-no-netpol"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  # network_profile block intentionally absent — network_policy defaults
  # to "none", leaving pods unrestricted.
}
