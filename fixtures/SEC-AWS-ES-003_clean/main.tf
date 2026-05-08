# Auto-generated clean fixture for SEC-AWS-ES-003.
# OpenSearch domain missing fine-grained access control
# This is a CORRECT configuration; SEC-AWS-ES-003 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_opensearch_domain" "example" {
  domain_name    = "example"
  engine_version = "OpenSearch_2.11"
  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = aws_iam_role.opensearch_admin.arn
    }
  }
}
