resource "aws_sqs_queue" "app" {
  name = "app-queue"
  # missing kms_master_key_id and sqs_managed_sse_enabled
}
