# Expected findings: NONE
# Guards against: SEC-SECRETS-ENTROPY-001
#
# None of these should trip the entropy detector — each exercises one of the
# false-positive exclusions:
resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"                       # cloud resource-id prefix
  instance_type = "t3.medium"                                   # too short / low entropy
  session_key   = var.session_key                               # variable reference, not a literal
  region        = "us-east-1"                                   # short, low entropy
  commit_sha    = "da39a3ee5e6b4b0d3255bfef95601890afd80709"    # hex / git-SHA, entropy < 4.0
  role_arn      = "arn:aws:iam::123456789012:role/app-runtime"  # not a token charset (has ':' '/')
  endpoint      = "https://prod.example.com/v1/ingest"          # URL, not a token charset
}
