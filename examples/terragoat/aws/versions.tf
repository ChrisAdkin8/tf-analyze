# AWS corpus — provider + Terraform version pinning.
#
# AWS catalogue coverage: SEC-AWS-ECR-001, SEC-AWS-VPC-FLOWLOGS-001,
# SEC-AWS-S3-PUBLIC-BLOCK-001, SEC-AWS-SQS-001, SEC-AWS-SNS-001,
# ROB-AWS-BACKEND-001, COST-AWS-RISK-001, SEC-SECRETS-001, and more.
# See the expected-findings comments in each .tf file.

terraform {
  required_version = ">= 1.10.0"

  # S3 backend without DynamoDB state locking — ROB-AWS-BACKEND-001
  backend "s3" {
    bucket = "demo-tf-state"
    key    = "terragoat/aws/terraform.tfstate"
    region = "us-east-1"
    # dynamodb_table intentionally omitted — concurrent applies can corrupt state
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}
