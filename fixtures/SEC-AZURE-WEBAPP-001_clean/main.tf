# Auto-generated clean fixture for SEC-AZURE-WEBAPP-001.
# Azure App Service / Function App missing IP access restrictions
# This is a CORRECT configuration; SEC-AZURE-WEBAPP-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  site_config {
    ip_restriction {
      ip_address = "203.0.113.0/24"
      name       = "allow-corporate"
      priority   = 100
      action     = "Allow"
    }
    scm_ip_restriction {
      ip_address = "203.0.113.0/24"
      name       = "allow-corporate"
      priority   = 100
      action     = "Allow"
    }
  }
}
