# Auto-generated clean fixture for OPS-AZURE-TAGS-001.
# Azure resource missing tags
# This is a CORRECT configuration; OPS-AZURE-TAGS-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "azurerm_resource_group" "example" {
  # ... other arguments ...
  tags = {
    Environment = "prod"
    Owner       = "platform-team"
    Project     = "my-project"
  }
}
