## count and for_each rules read the resource, not the file text

Findings change: fewer false alarms from comments, nested blocks and
`dynamic` blocks; a few missed `count` problems now caught.

- **Own arguments only**: `count_foreach_mix`, `count_length_unguarded`,
  `foreach_over_list` and `foreach_keyset_unstable` matched `count =` /
  `for_each =` anywhere in a resource — a Cloud Armor
  `rate_limit_threshold { count = 100 }` or a `dynamic "ingress" {
  for_each = [80, 443] }` was read as the resource's own. They now read
  the resource's top-level argument from the parse tree (regex fallback:
  top-level, comment-aware).
- **`count = var.on ? 1 : 0 # note`** (`ROB-COUNT-001`) was missed
  because of the trailing comment, and so was a ternary split over
  lines. Commented-out `count` lines no longer match.
- **`ROB-COUNTNAME-001`** reads the resource's name attributes and its
  `Name` tag, not a commented-out line; `bucket = format(...)` over
  several lines is caught when the file parses.
- **`ROB-COUNTREF-001` / `-002`** skip references in comments (including
  `/* */`), a `?` in a comment is no longer a guard, and a guard on a
  line that opens a bracket around the reference counts
  (`cond ? (\n  x[0].id\n) : null`).
- New `_hcl.attach_tree_attrs` gives corpus handlers the same parse
  tree `detect_in_file` gives in-file handlers.
