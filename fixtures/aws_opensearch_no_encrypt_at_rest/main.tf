# Expected findings:
#  - SEC-AWS-ES-001 HIGH — encrypt_at_rest missing

resource "aws_opensearch_domain" "main" {
  domain_name    = "main"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "r6g.large.search"
  }
  # encrypt_at_rest block intentionally absent
}
