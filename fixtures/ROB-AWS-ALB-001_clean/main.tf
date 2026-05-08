resource "aws_lb" "app" {
  name                       = "app-lb"
  internal                   = false
  load_balancer_type         = "application"
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  subnets                    = ["subnet-abc", "subnet-def"]
}
