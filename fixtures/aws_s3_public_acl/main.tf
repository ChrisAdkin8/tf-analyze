# Expected findings:
#  - SEC-AWS-S3-PUBLIC-001 HIGH — aws_s3_bucket_acl "public-read"
#  - SEC-AWS-S3-PUBLIC-001 HIGH — legacy inline acl "public-read-write"
#  - SEC-AWS-S3-PUBLIC-001 HIGH — access_control_policy grant to AllUsers
#  - SEC-AWS-S3-PUBLIC-001 HIGH — legacy inline grant to AuthenticatedUsers

resource "aws_s3_bucket" "site" {
  bucket = "my-site-bucket"
}

resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  acl    = "public-read"
}

resource "aws_s3_bucket" "legacy" {
  bucket = "my-legacy-bucket"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_acl" "grants" {
  bucket = aws_s3_bucket.site.id
  access_control_policy {
    grant {
      grantee {
        id   = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
        type = "CanonicalUser"
      }
      permission = "FULL_CONTROL"
    }
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AllUsers"
      }
      permission = "READ"
    }
    owner {
      id = "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
    }
  }
}

resource "aws_s3_bucket" "legacy_grant" {
  bucket = "my-legacy-grant-bucket"

  grant {
    type        = "Group"
    uri         = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    permissions = ["READ"]
  }
}
