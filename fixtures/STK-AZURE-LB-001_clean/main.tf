# Auto-generated clean fixture for STK-AZURE-LB-001.
# Azure Load Balancer missing diagnostic settings
# This is a CORRECT configuration; STK-AZURE-LB-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_monitor_diagnostic_setting" "lb" {
  name                       = "lb-diag"
  target_resource_id         = azurerm_lb.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  enabled_log {
    category = "LoadBalancerHealthEvent"
  }
}
