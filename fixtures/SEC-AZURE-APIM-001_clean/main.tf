# Auto-generated clean fixture for SEC-AZURE-APIM-001.
# Azure API Management missing diagnostic settings
# This is a CORRECT configuration; SEC-AZURE-APIM-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_api_management_diagnostic" "example" {
  identifier               = "applicationinsights"
  resource_group_name      = azurerm_resource_group.example.name
  api_management_name      = azurerm_api_management.example.name
  api_management_logger_id = azurerm_api_management_logger.example.id
  sampling_percentage      = 100
  always_log_errors        = true
}
