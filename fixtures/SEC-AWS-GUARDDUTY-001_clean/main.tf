resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_guardduty_detector" "example" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}
