# Expected findings:
#  - ROB-DRIFT-002 MEDIUM — ignore_changes = ["*"] (wildcard form)
#  - ROB-DRIFT-002 MEDIUM — ignore_changes = [tags] (tags-wide drift mask)

resource "aws_s3_bucket" "noisy_wildcard" {
  bucket = "wildcard-form"

  lifecycle {
    ignore_changes = ["*"]
  }
}

resource "aws_iam_role" "tags_wide" {
  name = "tags-wide"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = []
  })

  lifecycle {
    ignore_changes = [tags]
  }
}
