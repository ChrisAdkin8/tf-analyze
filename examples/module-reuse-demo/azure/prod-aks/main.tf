# Hand-rolled production AKS cluster + workload node pool + UAMI +
# diagnostic settings + Log Analytics + ACR + private DNS zone.
#
# Six supporting types present (threshold is 2) — Module Reuse Advisor
# fires MOD-REUSE-AZURE-AKS-001 with HIGH confidence. The community
# module `Azure/aks/azurerm` collapses all of this into ~30 lines of
# inputs.

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.50"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "this" {
  name     = "prod-aks-rg"
  location = "eastus"
}

resource "azurerm_kubernetes_cluster" "this" {
  name                = "prod-aks"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  dns_prefix          = "prodaks"

  default_node_pool {
    name           = "system"
    node_count     = 3
    vm_size        = "Standard_D4s_v5"
    vnet_subnet_id = null
    type           = "VirtualMachineScaleSets"

    only_critical_addons_enabled = true
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    load_balancer_sku = "standard"
  }

  role_based_access_control_enabled = true

  azure_active_directory_role_based_access_control {
    managed            = true
    azure_rbac_enabled = true
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "workload" {
  name                  = "workload"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  vm_size               = "Standard_D8s_v5"
  node_count            = 5

  enable_auto_scaling = true
  min_count           = 3
  max_count           = 20
}

resource "azurerm_user_assigned_identity" "kubelet" {
  name                = "prod-aks-kubelet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
}

resource "azurerm_role_assignment" "kubelet_acr_pull" {
  scope                = azurerm_container_registry.this.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.kubelet.principal_id
}

resource "azurerm_log_analytics_workspace" "aks" {
  name                = "prod-aks-logs"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                       = "prod-aks-diag"
  target_resource_id         = azurerm_kubernetes_cluster.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.aks.id

  enabled_log {
    category = "kube-apiserver"
  }

  enabled_log {
    category = "kube-audit"
  }

  metric {
    category = "AllMetrics"
  }
}

resource "azurerm_container_registry" "this" {
  name                = "prodaksacr"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = "Premium"
  admin_enabled       = false
}

resource "azurerm_private_dns_zone" "aks" {
  name                = "privatelink.eastus.azmk8s.io"
  resource_group_name = azurerm_resource_group.this.name
}
