# Expected findings:
#  - SEC-AWS-MSK-002 MEDIUM — no CMK for encryption at rest

resource "aws_msk_cluster" "main" {
  cluster_name           = "main"
  kafka_version          = "3.5.1"
  number_of_broker_nodes = 3

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = ["subnet-1", "subnet-2", "subnet-3"]
    security_groups = ["sg-1"]
    storage_info {
      ebs_storage_info { volume_size = 100 }
    }
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
    # No encryption_at_rest block — uses AWS-managed key
  }
}
