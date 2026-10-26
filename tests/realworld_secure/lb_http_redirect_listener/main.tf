resource "aws_lb_listener" "http" {
  load_balancer_arn = var.lb_arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type  = "redirect"
    order = 1

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

variable "lb_arn" {
  type        = string
  description = "ARN of the load balancer."
}
