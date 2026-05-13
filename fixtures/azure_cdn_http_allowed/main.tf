# Expected findings:
#  - SEC-AZURE-CDN-001 HIGH — is_http_allowed = true

resource "azurerm_cdn_endpoint" "http" {
  name                = "static"
  profile_name        = "edge"
  location            = "eastus"
  resource_group_name = "rg-main"
  is_http_allowed     = true
  is_https_allowed    = true

  origin {
    name      = "origin"
    host_name = "origin.example.com"
  }
}
