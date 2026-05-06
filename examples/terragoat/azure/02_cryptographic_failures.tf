# OWASP A02:2021 — Cryptographic Failures
# Cloud: Azure
#
# Six Azure cryptographic failure modes:
#
#   1. Storage account with `enable_https_traffic_only = false` —
#      HTTP traffic accepted alongside HTTPS, enabling
#      man-in-the-middle and credential harvesting.
#   2. Storage account with `min_tls_version = "TLS1_0"` — accepts
#      TLS 1.0 / 1.1 connections, both deprecated.
#   3. Key Vault without `purge_protection_enabled = true` and a
#      `soft_delete_retention_days` >= 7. A delete is unrecoverable
#      and an attacker can delete-and-recreate a secret with
#      attacker-controlled values under the same name.
#   4. SQL Server / SQL Database with TDE not enforced.
#   5. Disk encryption sets without customer-managed keys when the
#      regulatory regime requires CMEK.
#   6. Key Vault key without a rotation policy — the key is never
#      automatically rotated and grows stale indefinitely.
#
# Real-world impact:
#   - HTTP-accepting storage accounts are a routine credential-
#     harvest vector on coffee-shop wifi.
#   - Key Vaults without purge protection have been used in account-
#     takeover scenarios where the attacker deletes the legitimate
#     secret and substitutes their own.
#
# Expected tf-analyze findings:
#   - SEC-AZURE-STORAGE-001  HIGH  Azure storage account allows non-HTTPS / weak TLS
#   - SEC-AZURE-KV-001       HIGH  Azure Key Vault missing purge protection
#   - SEC-AZURE-KV-002       HIGH  Key Vault missing network ACL deny-by-default
#   - SEC-AZURE-KV-003       HIGH  Key Vault key missing rotation policy
#
# Fix summary: every storage account gets `enable_https_traffic_only
# = true` and `min_tls_version = "TLS1_2"`; every Key Vault gets
# `purge_protection_enabled = true` and a retention floor of 7 days;
# every key gets a `rotation_policy` block with automatic rotation.

# Storage account with HTTPS-only off and weak TLS floor.
resource "azurerm_storage_account" "weak_tls" {
  name                            = "demoweaktls1234"
  resource_group_name             = azurerm_resource_group.demo.name
  location                        = azurerm_resource_group.demo.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  enable_https_traffic_only       = false
  min_tls_version                 = "TLS1_0"
  allow_nested_items_to_be_public = false
}

# Key Vault key without a rotation policy — the cryptographic key
# is never rotated automatically; it stays valid indefinitely.
resource "azurerm_key_vault_key" "no_rotation" {
  name         = "demo-key-no-rotation"
  key_vault_id = azurerm_key_vault.no_purge_protection.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "verify"]
  # No rotation_policy block — key never rotates
}

# Key Vault without purge protection — deletes are permanent and
# delete-then-recreate replays are possible.
resource "azurerm_key_vault" "no_purge_protection" {
  name                       = "demo-kv-no-purge"
  resource_group_name        = azurerm_resource_group.demo.name
  location                   = azurerm_resource_group.demo.location
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
}
