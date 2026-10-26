resource "azurerm_redis_cache" "app" {
  name                          = "acme-app-cache"
  location                      = "uksouth"
  resource_group_name           = "rg-app"
  capacity                      = 1
  family                        = "C"
  sku_name                      = "Standard"
  public_network_access_enabled = false

  redis_configuration {}

  lifecycle {
    prevent_destroy = true
  }
}
