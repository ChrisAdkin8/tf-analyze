# Expected findings:
#  - SEC-AZURE-AKS-DEFENDER-001 HIGH — no microsoft_defender block

resource "azurerm_kubernetes_cluster" "no_defender" {
  name                    = "no-def"
  location                = "eastus"
  resource_group_name     = "rg-main"
  dns_prefix              = "app"
  private_cluster_enabled = true

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2s_v3"
  }

  identity {
    type = "SystemAssigned"
  }
}
