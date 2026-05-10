# Clean fixture: every ignore_changes list stays under the 5-attribute
# threshold. ROB-DRIFT-002 owns the wildcard / [tags] case; this rule
# does not fire on those (handled separately).

resource "aws_autoscaling_group" "app" {
  name = "app-asg"

  lifecycle {
    ignore_changes = [
      desired_capacity,
      target_group_arns,
    ]
  }
}

resource "aws_lambda_function" "fn" {
  function_name = "fn"
  role          = "arn:aws:iam::123:role/lambda"
  handler       = "index.handler"

  lifecycle {
    ignore_changes = [
      filename,
      source_code_hash,
    ]
  }
}

# Negative: no lifecycle block at all — must not fire.
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
