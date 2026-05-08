# Expected findings: SEC-AWS-DDB-001
resource "aws_dynamodb_table" "app" {
  name         = "app"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # server_side_encryption block absent — uses Amazon-owned keys, no CMK
}
