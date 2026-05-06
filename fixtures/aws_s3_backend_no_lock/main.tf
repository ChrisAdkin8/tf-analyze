# Expected findings:
#  - ROB-AWS-BACKEND-001 HIGH — S3 backend missing dynamodb_table state locking

terraform {
  required_version = ">= 1.0"

  backend "s3" {
    bucket  = "my-terraform-state"
    key     = "terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
    # dynamodb_table intentionally omitted — ROB-AWS-BACKEND-001 fires.
  }
}
