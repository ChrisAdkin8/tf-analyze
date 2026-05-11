# Clean fixture for ROB-COUNTNAME-001.
# The same shape migrated to for_each with stable string keys.
# Removing one element only destroys that one — others retain their
# state addresses *and* their external names.

resource "aws_instance" "web" {
  for_each      = toset(["alpha", "beta", "gamma"])
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  tags = {
    Name = "web-${each.key}"
  }
}

resource "aws_s3_bucket" "data" {
  for_each = toset(["events", "ledger"])
  bucket   = "myapp-data-${each.key}"
}

resource "aws_iam_user" "service" {
  for_each = toset(["pipeline", "ingest", "billing", "audit"])
  name     = each.key
}

# Negative case: count.index used in *non*-name attributes is fine —
# the engine only flags name-like attributes because they're what
# couples Terraform identity to external identity.
resource "aws_cloudwatch_log_group" "fan_out" {
  count             = 3
  name              = "log-group-stable"
  retention_in_days = count.index + 1
}
