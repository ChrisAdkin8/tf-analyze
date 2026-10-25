# Expected findings:
# - SEC-SECRETS-ENTROPY-001 HIGH high-entropy token hardcoded in a resource argument
#
# The token lives in an oddly-named field (`session_key`) that the name-based
# grep secret rules (SEC-SECRETS-001 matches password/secret/api_key) do NOT
# look at — this is exactly the gap entropy detection closes.
resource "aws_instance" "app" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"
  session_key   = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
}
