# Expected findings:
#  - STK-GCP-CLOUDARMOR-001 MEDIUM — no rule defined (allow-all default)

resource "google_compute_security_policy" "empty" {
  name        = "edge-policy"
  description = "Cloud Armor policy with no rules"
  # No rule block -- defaults to allow-all.
}
