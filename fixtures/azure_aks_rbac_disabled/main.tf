# Expected findings:
#  - SEC-AZURE-AKS-001 HIGH — role_based_access_control_enabled = false

resource "azurerm_kubernetes_cluster" "no_rbac" {
  name                = "no-rbac-aks"
  location            = "eastus"
  resource_group_name = "example-rg"
  dns_prefix          = "no-rbac-aks"

  role_based_access_control_enabled = false

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
