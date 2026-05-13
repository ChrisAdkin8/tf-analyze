# Expected findings:
#  - COST-AZURE-RISK-001 MEDIUM — Log Analytics workspace without daily_quota_gb

resource "azurerm_log_analytics_workspace" "no_quota" {
  name                = "law-main"
  location            = "eastus"
  resource_group_name = "rg-main"
  sku                 = "PerGB2018"
  # No daily_quota_gb -- uncapped ingestion billing.
}
