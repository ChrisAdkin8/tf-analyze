resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_kubernetes_cluster" "no_ip_ranges" {
  name                = "aks-no-ip-ranges"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  dns_prefix          = "aks-no-ip-ranges"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  # api_server_access_profile block absent — API server accepts
  # connections from any IP.
}
