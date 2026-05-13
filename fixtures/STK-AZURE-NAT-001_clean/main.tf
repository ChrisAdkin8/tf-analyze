# Auto-generated clean fixture for STK-AZURE-NAT-001.
# Azure NAT Gateway missing diagnostic settings
# This is a CORRECT configuration; STK-AZURE-NAT-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_monitor_diagnostic_setting" "nat" {
  name                       = "nat-diag"
  target_resource_id         = azurerm_nat_gateway.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
