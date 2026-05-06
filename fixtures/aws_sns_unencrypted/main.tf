resource "aws_sns_topic" "alerts" {
  name = "alerts"
  # missing kms_master_key_id
}
