# Expected findings:
#  - ROB-AWS-LIFECYCLE-001 HIGH — aws_dynamodb_table missing lifecycle.prevent_destroy
#  - ROB-AWS-LIFECYCLE-001 HIGH — aws_db_instance missing lifecycle.prevent_destroy
#  - ROB-AWS-LIFECYCLE-001 HIGH — aws_s3_bucket missing lifecycle.prevent_destroy

resource "aws_dynamodb_table" "orders" {
  name         = "orders"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # No lifecycle block — table can be accidentally destroyed.
}

resource "aws_db_instance" "app" {
  identifier     = "app-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  username       = "admin"
  password       = var.db_password

  # No lifecycle block.
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  # No lifecycle block.
}
