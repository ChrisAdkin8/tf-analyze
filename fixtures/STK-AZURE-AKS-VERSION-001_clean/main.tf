# Auto-generated clean fixture for STK-AZURE-AKS-VERSION-001.
# Azure AKS cluster on end-of-life Kubernetes version
# This is a CORRECT configuration; STK-AZURE-AKS-VERSION-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_kubernetes_cluster" "example" {
  name                = "example"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "example"
  kubernetes_version  = "1.29.4"
  default_node_pool { name = "default" node_count = 1 vm_size = "Standard_D2s_v3" }
  identity { type = "SystemAssigned" }
}
