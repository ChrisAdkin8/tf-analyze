# Expected findings:
#  - SEC-AWS-LB-LISTENER-002 HIGH — TLS-1.0 policy on HTTPS listener

resource "aws_lb_listener" "https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/foo/abc"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2017-01"
  certificate_arn   = "arn:aws:acm:us-east-1:123:certificate/abc"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/foo/abc"
  }
}
