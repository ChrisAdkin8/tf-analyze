# Expected findings:
#  - ROB-AWS-ALB-001 MEDIUM — deletion protection absent on aws_lb

resource "aws_lb" "app" {
  name               = "app-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-abc123", "subnet-def456"]
  # enable_deletion_protection intentionally absent
}
