# Expected findings:
#  - SEC-AZURE-APIM-002 MEDIUM — no product policy bound

resource "azurerm_api_management_product" "free" {
  product_id            = "free-tier"
  api_management_name   = "api-mgmt"
  resource_group_name   = "rg-main"
  display_name          = "Free tier"
  subscription_required = true
  approval_required     = false
  published             = true
}
