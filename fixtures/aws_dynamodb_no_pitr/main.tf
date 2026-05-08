# Expected findings: ROB-AWS-DDB-002
resource "aws_dynamodb_table" "app" {
  name         = "app"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # point_in_time_recovery block is absent — defaults to disabled
}
