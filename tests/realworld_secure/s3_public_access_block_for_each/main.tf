variable "buckets" {
  type        = set(string)
  description = "Bucket names."
  default     = ["acme-a", "acme-b"]
}

resource "aws_s3_bucket" "many" {
  for_each = var.buckets
  bucket   = each.value

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "many" {
  for_each = aws_s3_bucket.many
  bucket   = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "many" {
  for_each = aws_s3_bucket.many
  bucket   = each.value.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
