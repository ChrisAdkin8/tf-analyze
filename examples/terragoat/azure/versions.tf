# Azure corpus — provider + Terraform version pinning.
#
# Azure-specific catalogue coverage in tf-analyze is currently 1
# active rule (SEC-AZURE-RBAC-001) plus 4 stubs (SEC-AZURE-STORAGE-001,
# SEC-AZURE-KV-001, STK-AZURE-NSG-001, SEC-AZURE-MI-001). The corpus
# documents OWASP categories with realistic Azure anti-patterns and
# serves as a roadmap for promoting the stubs.

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.50"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

resource "azurerm_resource_group" "demo" {
  name     = "demo-rg"
  location = "westeurope"
}
