# Expected findings:
#  - ROB-DRIFT-003 LOW — `aws_autoscaling_group.app` ignore_changes
#    list has 7 attributes (threshold: 5). Drift detection is
#    effectively disabled by attrition.

resource "aws_autoscaling_group" "app" {
  name             = "app-asg"
  min_size         = 1
  max_size         = 10
  desired_capacity = 3

  lifecycle {
    ignore_changes = [
      desired_capacity,
      target_group_arns,
      load_balancers,
      tag,
      health_check_grace_period,
      health_check_type,
      vpc_zone_identifier,
    ]
  }
}

# Negative case — exactly 3 attributes, well under threshold.
resource "aws_lambda_function" "ok" {
  function_name = "ok"
  role          = "arn:aws:iam::123:role/lambda"
  handler       = "index.handler"

  lifecycle {
    ignore_changes = [
      filename,
      source_code_hash,
      last_modified,
    ]
  }
}
