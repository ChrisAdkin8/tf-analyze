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
- **One odd field lost a whole policy**: a `jsonencode` policy with both
  `format("s-%s", var.n)` and `var.w ? ["a"] : ["b"]` in it could not be
  read, because the parser prints the first with raw double quotes and the
  second with Python's single quotes, so an admin statement beside them
  was never checked and nothing said so. Such a policy is now read, and a
  policy written out in the source that can't be decoded gets a WARN.
- **Parenthesised objects**: `ingress = ([{...}])`,
  `metadata_options = ({...})` and `inline_policy = ([{...}])` now read
  like the plain forms in every rule on the parse-tree path.
- **Fewer false positives**: `sensitive = (true)` counts as sensitive.
  STK-GCP-CLOUDSQL-004 reads `ssl_mode` rather than looking for its text,
  so the formatter's alignment and a commented-out line no longer change
  the result, and `TRUSTED_CLIENT_CERTIFICATE_REQUIRED` passes as the rule
  always said it should. `hcl_attr` patterns now accept `suppress_if`.
- **Regex fallback misses IAM policies**: one construct the parser rejects,
  anywhere in a file, left `policy = jsonencode(` as the only form read, so
  heredoc and JSON-string policies, `inline_policy` blocks and bucket
  policies passed with only a WARN. The argument, or the
  `aws_iam_policy_document` block, is now cut from the text and parsed on
  its own, so it reads as it does in a clean file, `dynamic "statement"`
  and `inline_policy = [{...}]` included. `/* */` between block labels no
  longer loses the block. `--fail-on-parse-error` is unchanged.
- **Ninth caller of a shared module**: only the first 8 distinct sets of
  caller inputs were scanned and the rest dropped without a word, so a lone
  `acl = "public-read"` caller behind eight others with different names
  exited 0. The limit is now 64. Past it, inputs that only a resource's tags
  read stop counting, and if there are still too many, the sets are chosen
  so each value of each input is scanned while the limit allows, and the
  scan reports what it left out: a WARN, `summary.unscanned_contexts`, and
  `--fail-on` and the GitHub Action's gate fail, as for a rule check that ran
  out of time. **A repo with a local module that has more than 64 distinct
  callers now fails `--fail-on`.**
