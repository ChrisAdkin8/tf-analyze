# Expected findings:
# - SEC-AWS-IAM-JSON-003 CRITICAL aws_iam_role.admin_but_one (Action "*" + NotResource)
# - SEC-AWS-IAM-POLICY-005 CRITICAL data.aws_iam_policy_document.admin_but_one
#
# `Action: "*"` with `NotResource` allows every action on every resource
# except the one listed: AdministratorAccess in all but name. It used to be
# reported only as a HIGH wildcard action (SEC-AWS-IAM-JSON-001).

resource "aws_iam_role" "admin_but_one" {
  name               = "admin-but-one"
  assume_role_policy = "{}"

  inline_policy {
    name = "everything-else"
    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Effect = "Allow", Action = "*", NotResource = "arn:aws:s3:::audit-bucket" }]
    })
  }
}

data "aws_iam_policy_document" "admin_but_one" {
  statement {
    actions       = ["*"]
    not_resources = ["arn:aws:s3:::audit-bucket"]
  }
}
