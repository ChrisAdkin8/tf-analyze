# Auto-generated clean fixture for STK-AZURE-AKS-005.
# AKS cluster API server missing authorized IP ranges
# This is a CORRECT configuration; STK-AZURE-AKS-005 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  dns_prefix          = "example"
  api_server_access_profile {
    authorized_ip_ranges = ["203.0.113.0/24"]
  }
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
  identity { type = "SystemAssigned" }
}
