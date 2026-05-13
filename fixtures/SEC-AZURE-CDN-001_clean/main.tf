# Auto-generated clean fixture for SEC-AZURE-CDN-001.
# Azure CDN endpoint allows plain HTTP
# This is a CORRECT configuration; SEC-AZURE-CDN-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_cdn_endpoint" "example" {
  name                = "example"
  profile_name        = azurerm_cdn_profile.example.name
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  is_http_allowed     = false
  is_https_allowed    = true
  origin {
    name      = "origin"
    host_name = "origin.example.com"
  }
}
