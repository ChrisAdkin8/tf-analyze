# Expected findings:
#  - ROB-COUNT-002 MEDIUM — same module mixes count and for_each across resources

resource "google_storage_bucket" "legacy" {
  count    = 2
  name     = "legacy-${count.index}"
  location = "US"
}

resource "google_storage_bucket" "modern" {
  for_each = toset(["a", "b"])
  name     = "modern-${each.key}"
  location = "US"
}
