# Auto-generated clean fixture for STK-AZURE-LOGIC-APP-001.
# Azure Logic App missing diagnostic settings
# This is a CORRECT configuration; STK-AZURE-LOGIC-APP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_monitor_diagnostic_setting" "logic" {
  name                       = "logic-diag"
  target_resource_id         = azurerm_logic_app_workflow.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id
  enabled_log {
    category = "WorkflowRuntime"
  }
}
