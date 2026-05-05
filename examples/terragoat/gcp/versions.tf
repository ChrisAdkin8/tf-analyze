# GCP corpus — provider + Terraform version pinning.
#
# required_version is pinned to >= 1.10.0 so SEC-EPHEMERAL-001 fires
# in any data source file that reads a Vault secret. Drop this floor
# below 1.10 and the rule is correctly skipped via the
# applies_when.min_terraform gate (covered by the
# `false_positive_vault_ds_old_tf` fixture under fixtures/).

terraform {
  required_version = ">= 1.10.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.40"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}
