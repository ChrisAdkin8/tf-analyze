# r/Terraform launch post

## Subreddit

[r/Terraform](https://www.reddit.com/r/Terraform/) — primary
[r/devsecops](https://www.reddit.com/r/devsecops/) — secondary, same body
[r/kubernetes](https://www.reddit.com/r/kubernetes/) — only if mentioning the K8s + Helm rule pack

## Title (≤ 300 chars, no spam-word triggers)

`I built a Terraform scanner that ranks fixes by attack-path centrality (not alphabetical rule ID)`

## Body

```markdown
Hey folks — wanted to share something I've been working on:
**[tf-analyze](https://github.com/ChrisAdkin8/tf-analyze)**.

The thing I kept hitting with tfsec and checkov was that the output
is a flat list. Sort by severity, sure, but you still don't know
*which fix to do first* if you have 30 HIGH findings.

tf-analyze builds an attack-path graph: internet-reachable resources
→ IAM roles → crown jewels (databases, KMS keys, secrets buckets).
Findings on the critical path get promoted one urgency tier; fixes
get ranked by how many crown jewels each one unblocks. So the report
opens with **"fix this first"**, not "alphabetical rule ID".

Other stuff that's specific to this:

- **209 rules**, all with a `fix_hcl` snippet. The GitHub Action posts
  them as inline ` ```suggestion ``` ` blocks — reviewers click **Apply
  suggestion** for one-click fixes. Saves a lot of "I'll get to it" PR
  drift.
- **HIGH/CRITICAL findings come with adversarial scenarios.** Hover
  over a flagged `aws_iam_role` in VS Code and you get the Capital
  One breach story in plain English. Apparently more memorable than
  "AC-3.1.4 violation".
- **Walks inline `policy = jsonencode({...})` blocks** as well as
  `data "aws_iam_policy_document"` — closes the gap most scanners
  have on hand-rolled JSON policies.
- **LSP server** so VS Code shows findings as you type, with Quick
  Fix actions to apply the snippet.
- **Deterministic risk score** (0–100, letter grade A–F) in JSON
  output with a `scoring_version`. CI can gate on `--fail-on HIGH`
  and dashboards can trend the score.

Stack is stdlib-only Python with optional `python-hcl2` fast-path.
Catalogue is one YAML per rule so adding a rule doesn't touch
engine code.

**Three things I'd love feedback on:**

1. Is the attack-graph framing useful, or noise? Sample reports
   against terragoat:
   https://github.com/ChrisAdkin8/tf-analyze/tree/main/reports
2. The risk-score formula is `max(0, 100 - 15·CRITICAL - 7·HIGH -
   3·MEDIUM - 1·LOW)` with suppressed findings at half weight. Is
   that defensible or do the weights feel off?
3. The IAM-policy rules (six checks: wildcard action / resource /
   public principal / `iam:*` privesc / full-admin / NotAction)
   are catching things in real codebases I've tested but I'd love
   reports of false positives.

Happy to answer questions. Repo is MPL-2.0.
```

## Notes

- r/Terraform's mods historically dislike pure self-promotion. The
  framing here is "I built X, would love feedback on Y, Z, W" — not
  "BUY MY THING".
- The IAM-JSON rule pack is the most novel/genuinely useful claim;
  lead with that if the post needs a shorter version.
- **Don't** crosspost to multiple subs in the same hour — Reddit's
  spam filter triggers. Stagger by ≥4 hours.
- Engagement plan: monitor for ≥6 hours. Mod questions about the
  rule schema, comparison vs tfsec, and "does this work with
  Terragrunt?" are likely.
