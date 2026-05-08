# Expected findings:
#  - SEC-AWS-KINESIS-001 MEDIUM — Kinesis stream not encrypted

resource "aws_kinesis_stream" "events" {
  name        = "events"
  shard_count = 2
  # No encryption_type set — defaults to NONE
}
