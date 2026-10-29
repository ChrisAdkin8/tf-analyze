## A `${ }` that runs onto the next line no longer cuts a block short

- **Block bodies**: Terraform accepts a line break inside an
  interpolation (`name = "${join("-", [` then `var.env, "s"])}"` on the
  next line). The block finder ended every quoted string at its first
  line, so the `}` of `])}` closed the enclosing block early and the rest
  of the resource was invisible to every text-based rule: a
  `kubernetes_secret` with a literal password after such a name was not
  reported. An interpolation can now run onto later lines.
- **Recovery is unchanged**: a string that still never closes ends on its
  own line, as before, so one stray `"${` costs only its line.
