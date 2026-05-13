# Auto-generated clean fixture for SEC-AZURE-APIM-002.
# Azure API Management product without rate-limit policy
# This is a CORRECT configuration; SEC-AZURE-APIM-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_api_management_product_policy" "example" {
  product_id          = azurerm_api_management_product.example.product_id
  api_management_name = azurerm_api_management.example.name
  resource_group_name = azurerm_resource_group.example.name
  xml_content         = "<policies><inbound><rate-limit-by-key calls=\"100\" renewal-period=\"60\" counter-key=\"@(context.Subscription.Key)\" /><base /></inbound></policies>"
}
