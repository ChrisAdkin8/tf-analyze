# Azure corpus — provider + Terraform version pinning.
#
# Azure catalogue coverage: SEC-AZURE-RBAC-001, SEC-AZURE-STORAGE-001,
# SEC-AZURE-KV-001, SEC-AZURE-MI-001, STK-AZURE-NSG-FLOWLOG-001,
# ROB-AZURE-LIFECYCLE-001, SEC-SECRETS-001, and more.
# See the expected-findings comments in each .tf file.

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
