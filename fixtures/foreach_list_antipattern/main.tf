# Expected findings:
#  - ROB-FOREACH-001 MEDIUM — for_each over list/tuple causes churn when order changes; use a map/set

resource "google_storage_bucket" "example" {
  for_each = ["alpha", "beta", "gamma"]
  name     = each.value
  location = "US"
}
