# Expected findings:
#  - SEC-AZURE-REDIS-001 HIGH — non-SSL port enabled, TLS below 1.2

resource "azurerm_redis_cache" "main" {
  name                = "main"
  resource_group_name = "rg-main"
  location            = "eastus"
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = true
  minimum_tls_version = "1.0"
}
