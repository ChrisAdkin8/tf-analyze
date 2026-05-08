# Auto-generated clean fixture for SEC-AWS-MSK-001.
# MSK cluster allows unencrypted client-broker traffic
# This is a CORRECT configuration; SEC-AWS-MSK-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_msk_cluster" "example" {
  cluster_name = "example"
  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}
