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
  was never checked and nothing said so. Such a policy is now read.
  Statement objects written out inside `concat(...)`, `flatten(...)`, a
  conditional or `tostring(...)` are analysed too. A `merge(...)` counts as
  one object: the objects written out in the call merge in order, later
  keys winning, and `var.X`, `local.X` and `data.X` are not followed, even
  with a default. After an unknown argument a literal Allow stands and is
  reported; a literal Deny, or no `Effect` at all, is unknown, which gets a
  WARN and no finding. A
  policy written out in the source that still can't be read, in whole or
  in part (more than 1,000 objects in one expression included), gets a
  WARN. `data.x.json`, `file(...)` and `jsonencode(var.p)` hold no document,
  so they get none.
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
  exited 0. Every set is now scanned, within a budget of contexts x resources
  (about 200,000 a module and 1,000,000 a repo; `--max-module-contexts N`,
  or the Action's `max-module-contexts` input, sets a plain count instead).
  An input that is a bare unresolved reference (`aws_subnet.a.id`), or a list
  or plain object of nothing but those, no longer makes a set distinct. Past
  the budget, inputs the module doesn't read stop
  counting, and the sets are chosen so each value of each input is scanned.
  A value left out fails `--fail-on` and the Action's gate, naming the
  module (`summary.unscanned_contexts`); in `--mode diff`, only for modules
  the change touches. **Residual risk:** with every value scanned but not
  every combination, the scan gives only a WARN
  (`summary.unscanned_combinations`), so a finding needing two values from
  different callers together can be missed.
- **`--mode verify-fixed`**: a finding gone from a module with callers left
  out, or from a module below it, came out RESOLVED while still live. It is
  now UNREADABLE, and the mode gates on left-out values and on rule checks
  that ran out of time. `--cache` keys on `--max-module-contexts` and does
  not save a scan with callers left out.
- **Engine keys in the variable table**: `__aws_default_tags__ = "true"` in a
  tfvars file removed the tag rules, and `__local__a` set from tfvars or a
  caller changed what `local.a` read. Names from scanned code can no longer
  set these.
- **Escaped quotes in expressions**: a string inside a `jsonencode`
  expression lost its escapes, so its text could read as code and turn an
  admin Allow into a Deny.
