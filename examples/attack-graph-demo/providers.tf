# Misconfigured 3-tier app — the canonical "small startup that grew
# fast" architecture. See README.md for the attack-path narrative.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "attack-graph-demo"
      Environment = "prod"
      ManagedBy   = "terraform"
    }
  }
}

variable "app_name" {
  type    = string
  default = "demoapp"
}
