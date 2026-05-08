# Expected findings:
#  - SEC-AWS-ES-003 HIGH — fine-grained access control missing

resource "aws_opensearch_domain" "main" {
  domain_name    = "main"
  engine_version = "OpenSearch_2.11"

  encrypt_at_rest {
    enabled    = true
    kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc-123"
  }
  node_to_node_encryption {
    enabled = true
  }
  # advanced_security_options intentionally absent
}
