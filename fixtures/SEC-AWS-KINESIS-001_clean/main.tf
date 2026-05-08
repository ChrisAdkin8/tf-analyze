resource "aws_kinesis_stream" "example" {
  name             = "example-stream"
  shard_count      = 1
  encryption_type  = "KMS"
  kms_key_id       = "alias/aws/kinesis"
}
