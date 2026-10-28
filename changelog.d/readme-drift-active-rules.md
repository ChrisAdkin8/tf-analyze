## Rule counts mean rules that run

- **README drift test** counted every rule that wasn't deprecated, so the
  two stubs (`STK-K8S-IMAGE-SIGNED-001`, `SEC-LOG-CROSS-ACCOUNT-001`) made
  the README claim 354 rules while `--list-rules` and every scan use 352.
  It now counts `status: active` only, and also checks the "Rules at a
  glance" table (total and row sum) and SKILL.md's total.
- **Corrected counts**: rules badge 352, D3FEND 47%, the table's K8s / Helm
  and cross-cloud rows, and SKILL.md's per-cloud table (it still said 91
  rules for every cloud). The rule-docs badge stays at 354: stubs have
  pages too.
