# Expected findings:
#  - STK-DEFAULTS-001 MEDIUM — module directory has no required_version

resource "aws_s3_bucket" "data" {
  bucket = "data-no-pin"
}
