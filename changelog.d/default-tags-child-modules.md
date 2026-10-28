## Provider `default_tags` reach child modules

Findings change: fewer missing-tags findings in local child modules.

- **Inheritance**: the AWS provider's `default_tags` were recorded only for
  the folder that declares the provider, so every untagged resource in a
  local child module got `OPS-AWS-TAGS-001` (and the other `tags` rules on
  `aws_*` resources) even though Terraform applies the tags there too. They
  now flow down module calls with the caller's other values, through any
  depth, and follow `providers = { aws = aws.<alias> }`: a child counts as
  covered only when the configuration it is given has `default_tags`. A
  child called from a caller without them is still reported. Remote module
  sources aren't scanned, so nothing changes for them.
