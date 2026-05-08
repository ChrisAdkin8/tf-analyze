# Auto-generated clean fixture for SEC-AWS-ES-001.
# OpenSearch / Elasticsearch domain missing encryption at rest
# This is a CORRECT configuration; SEC-AWS-ES-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_opensearch_domain" "example" {
  domain_name    = "example"
  engine_version = "OpenSearch_2.11"
  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.es.arn
  }
}
