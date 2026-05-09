# Expected findings:
#  - MOD-REUSE-AZURE-AKS-001 INFO — hand-rolled AKS cluster + node
#    pool + identity + diagnostics matches the shape of Azure/aks/azurerm.

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "demo-aks"
  location            = "eastus"
  resource_group_name = "demo-rg"
  dns_prefix          = "demoaks"

  default_node_pool {
    name       = "system"
    node_count = 2
    vm_size    = "Standard_D2s_v5"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "workload" {
  name                  = "workload"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.aks.id
  vm_size               = "Standard_D4s_v5"
  node_count            = 3
}

resource "azurerm_user_assigned_identity" "kubelet" {
  name                = "kubelet-id"
  location            = "eastus"
  resource_group_name = "demo-rg"
}

resource "azurerm_log_analytics_workspace" "aks_logs" {
  name                = "aks-logs"
  location            = "eastus"
  resource_group_name = "demo-rg"
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "aks-diag"
  target_resource_id         = azurerm_kubernetes_cluster.aks.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.aks_logs.id

  enabled_log {
    category = "kube-apiserver"
  }

  metric {
    category = "AllMetrics"
  }
}
