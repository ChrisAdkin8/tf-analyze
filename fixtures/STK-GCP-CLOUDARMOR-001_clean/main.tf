# Auto-generated clean fixture for STK-GCP-CLOUDARMOR-001.
# GCP Cloud Armor security policy missing rate-based rule
# This is a CORRECT configuration; STK-GCP-CLOUDARMOR-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "google_compute_security_policy" "example" {
  name = "example"

  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config { src_ip_ranges = ["*"] }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }
}
