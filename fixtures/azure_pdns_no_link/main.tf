# Expected findings:
#  - SEC-AZURE-PRIVATE-DNS-001 LOW — no vnet link bound

resource "azurerm_private_dns_zone" "orphan" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = "rg-main"
}
