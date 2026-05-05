# Pinned to TF 1.10+ so SEC-EPHEMERAL-001 fires on the data sources in
# secrets.tf. If you drop this to <1.10 the rule correctly skips itself
# (covered by the `false_positive_vault_ds_old_tf` fixture).

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}
