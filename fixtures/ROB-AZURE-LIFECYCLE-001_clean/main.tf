# Auto-generated clean fixture for ROB-AZURE-LIFECYCLE-001.
# Stateful Azure resource missing lifecycle.prevent_destroy
# This is a CORRECT configuration; ROB-AZURE-LIFECYCLE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_storage_account" "example" {
  # ... other arguments ...
  lifecycle {
    prevent_destroy = true
  }
}
