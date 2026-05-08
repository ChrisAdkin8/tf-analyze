# Auto-generated clean fixture for SEC-AWS-ELASTICACHE-001.
# ElastiCache replication group missing encryption
# This is a CORRECT configuration; SEC-AWS-ELASTICACHE-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_elasticache_replication_group" "example" {
  # ... other arguments ...
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = var.auth_token
}
