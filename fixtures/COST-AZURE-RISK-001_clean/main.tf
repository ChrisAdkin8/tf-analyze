# Auto-generated clean fixture for COST-AZURE-RISK-001.
# Azure resource missing cost control
# This is a CORRECT configuration; COST-AZURE-RISK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_kubernetes_cluster_node_pool" "main" {
  name                  = "default"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_D2s_v3"
  enable_auto_scaling   = true
  min_count             = 1
  max_count             = 5
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-main"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  daily_quota_gb      = 10
}
