resource "aws_cloudwatch_log_group" "app" {
  name = "/app/logs"
  # missing retention_in_days — logs retained indefinitely
}

resource "aws_autoscaling_group" "app" {
  min_size           = 1
  # missing max_size — runaway scale-out risk
  desired_capacity   = 2
  availability_zones = ["us-east-1a"]
}
