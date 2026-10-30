## A value's shape, a rejected file or a ninth caller no longer hide a finding

- **Wrapped literals**: `acl = ("public-read")`, `acl = "${"public-read"}"`
  and `cidr_blocks = (["0.0.0.0/0"])` exited 0, while the plain forms were
  reported. `resolve_value_text` took the brackets off only to look for a
  `var.X`, so a literal came back wrapped and no regex matched. A literal
  now loses parentheses and `${...}`, however nested, for every rule that
  resolves values, the firewall path, `helm_set_value`, IAM statements and
  caller inputs. Non-literal expressions are left as they were. One side
  effect: a parenthesised known value now counts, so `count = (0)` skips
  the resource and `type = ("egress")` is no longer treated as maybe-ingress.
- **Parenthesised `jsonencode`**: `policy = (jsonencode({...}))` was not
  analysed at all, because the policy reader wanted `jsonencode` at the very
  start of the value. Every form the formatter leaves is now read, and so
  are parenthesised heredocs and JSON strings, and parenthesised fields
  (`Action = ("*")`, `Effect = ("Deny")`, `actions = (["*"])`).
- **Regex fallback misses IAM policies**: one construct the parser rejects,
  anywhere in a file, left `policy = jsonencode(` as the only form read, so
  heredoc and JSON-string policies, `inline_policy` blocks and bucket
  policies passed with only a WARN. The argument, or the
  `aws_iam_policy_document` block, is now cut from the text and parsed on
  its own, so it reads as it does in a clean file, `dynamic "statement"`
  included. `/* */` between block labels no longer loses the block.
  `--fail-on-parse-error` is unchanged.
- **Ninth caller of a shared module**: only the first 8 distinct sets of
  caller inputs were scanned and the rest dropped without a word, so a lone
  `acl = "public-read"` caller behind eight others with different names
  exited 0. The limit is now 64, and past it the sets are chosen so each
  value of each input is scanned, with the inputs that have fewest values
  first. A WARN names the module and how many sets were not scanned.
