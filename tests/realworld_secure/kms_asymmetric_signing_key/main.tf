resource "aws_kms_key" "signing" {
  description              = "Release artefact signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
}
