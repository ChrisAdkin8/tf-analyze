# Expected findings:
#  - STK-AZURE-AKS-AUTOSCALE-001 LOW — enable_auto_scaling = false

resource "azurerm_kubernetes_cluster" "fixed" {
  name                = "fixed"
  location            = "eastus"
  resource_group_name = "rg-main"
  dns_prefix          = "app"

  default_node_pool {
    name                = "default"
    node_count          = 3
    enable_auto_scaling = false
    vm_size             = "Standard_D2s_v3"
  }

  identity {
    type = "SystemAssigned"
  }
}
