# Clean baseline for SEC-AWS-WAF-002.
# The web ACL has two `rule` blocks: a managed rule group and a rate-based
# rule. One rate-based rule is enough, so the rule must NOT fire — this
# pins the pattern's `instances: any` (a web ACL's other rules don't need
# a rate_based_statement of their own).

resource "aws_wafv2_web_acl" "edge" {
  name  = "edge"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "managed-common"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "managed-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "edge"
    sampled_requests_enabled   = true
  }
}
