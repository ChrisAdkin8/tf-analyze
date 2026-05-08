# Auto-generated clean fixture for SEC-AWS-ES-002.
# OpenSearch / Elasticsearch domain missing node-to-node encryption
# This is a CORRECT configuration; SEC-AWS-ES-002 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_opensearch_domain" "example" {
  domain_name    = "example"
  engine_version = "OpenSearch_2.11"
  node_to_node_encryption {
    enabled = true
  }
}
