# Expected findings:
#  - SEC-AZURE-AKS-OMS-001 MEDIUM — no oms_agent block

resource "azurerm_kubernetes_cluster" "no_oms" {
  name                    = "no-oms"
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

  microsoft_defender {
    log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/rg-main/providers/Microsoft.OperationalInsights/workspaces/law"
  }
}
