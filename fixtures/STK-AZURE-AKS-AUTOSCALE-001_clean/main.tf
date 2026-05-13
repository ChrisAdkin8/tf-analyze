# Auto-generated clean fixture for STK-AZURE-AKS-AUTOSCALE-001.
# Azure AKS default node pool missing auto-scaling
# This is a CORRECT configuration; STK-AZURE-AKS-AUTOSCALE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "example"
  default_node_pool {
    name                = "default"
    enable_auto_scaling = true
    min_count           = 1
    max_count           = 10
    vm_size             = "Standard_D2s_v3"
  }
  identity { type = "SystemAssigned" }
}
