# Clean fixture for ROB-DRIFT-002.
# Per-key tag suppression is the recommended pattern — must NOT fire.

resource "aws_s3_bucket" "tidy" {
  bucket = "tidy"

  lifecycle {
    ignore_changes = [
      tags["LastModifiedBy"],
      tags["LastBackup"],
    ]
  }
}
