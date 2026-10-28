## Firewall rules fold a ternary that picks a list

Findings change: an open CIDR list chosen by a ternary is now caught.
Terragoat totals are unchanged.

- **List ternaries**: `cidr_blocks = var.open ? ["0.0.0.0/0"] : [...]`
  (and GCP `source_ranges`) did not fold, the gap Round 79 left open.
  Inside an expression python-hcl2 prints the list in Python's repr
  (`['0.0.0.0/0']`), and the HCL list reader kept the quotes on each
  item. `_network.parse_literal` now reads a list of plain strings and
  numbers with `ast.literal_eval` first, which accepts that form and
  plain HCL string lists without running anything; lists holding
  references or `true` / `false` are read as before. A condition with no
  known value is still not guessed.
