# Expected findings:
#  - SEC-AWS-LB-LISTENER-001 HIGH — plain HTTP listener without redirect

resource "aws_lb_listener" "http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/main/abc123"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/app/abc123"
  }
}
