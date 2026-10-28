resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}

resource "aws_s3_bucket_acl" "logs" {
  bucket = aws_s3_bucket.example.id
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_acl" "grants" {
  bucket = aws_s3_bucket.example.id
  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/s3/LogDelivery"
      }
      permission = "WRITE"
    }
    owner {
      id = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
    }
  }
}

resource "aws_s3_bucket" "legacy" {
  bucket = "my-legacy-bucket"
  acl    = "private"

  grant {
    id          = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
    type        = "CanonicalUser"
    permissions = ["FULL_CONTROL"]
  }
}
