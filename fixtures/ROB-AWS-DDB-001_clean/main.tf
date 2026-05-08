# Auto-generated clean fixture for ROB-AWS-DDB-001.
# DynamoDB table missing deletion protection
# This is a CORRECT configuration; ROB-AWS-DDB-001 must NOT fire here.
# Edit by hand if the rule needs additional context.

resource "aws_dynamodb_table" "example" {
  name                        = "example"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "id"
  deletion_protection_enabled = true

  attribute {
    name = "id"
    type = "S"
  }
}
