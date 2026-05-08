# Auto-generated clean fixture for SEC-AWS-LB-LISTENER-001.
# ALB listener serves plain HTTP without redirect
# This is a CORRECT configuration; SEC-AWS-LB-LISTENER-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.example.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
