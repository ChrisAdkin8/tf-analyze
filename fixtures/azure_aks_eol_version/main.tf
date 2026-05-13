# Expected findings:
#  - STK-AZURE-AKS-VERSION-001 HIGH — kubernetes_version = 1.25.x (EOL)

resource "azurerm_kubernetes_cluster" "eol" {
  name                    = "legacy"
  location                = "eastus"
  resource_group_name     = "rg-main"
  dns_prefix              = "app"
  kubernetes_version      = "1.25.6"
  private_cluster_enabled = true

  default_node_pool {
    name                = "default"
    node_count          = 3
    enable_auto_scaling = true
    min_count           = 1
    max_count           = 10
    vm_size             = "Standard_D2s_v3"
  }

  identity {
    type = "SystemAssigned"
  }
}
