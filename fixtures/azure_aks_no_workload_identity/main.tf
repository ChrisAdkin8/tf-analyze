resource "azurerm_resource_group" "main" {
  name     = "rg-app"
  location = "eastus"
}

resource "azurerm_kubernetes_cluster" "no_wi" {
  name                = "aks-no-wi"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  dns_prefix          = "aks-no-wi"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  # workload_identity_enabled absent — pods cannot use federated Azure AD
  # tokens; must use service principal secrets or node identity instead.
}
