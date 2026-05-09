# Hacker News submission

## Title

`Show HN: tf-analyze – Terraform scanner with attack-graph prioritisation`

(< 80 chars; HN's algorithm slightly favours "Show HN:" prefix.)

## URL

`https://github.com/ChrisAdkin8/tf-analyze`

## Text (for the comment, not the submission body)

```
Most Terraform scanners give you a flat list of findings. tf-analyze
builds a directed graph from internet-reachable resources to crown
jewels (databases, KMS keys, secrets) and ranks each fix by how many
crown jewels it unblocks. So the report opens with "fix this first"
ordered by attack-path centrality, not by alphabetical rule ID.

A few other things that distinguish it from tfsec / checkov:

- Every rule (209 of them) ships an HCL fix_hcl snippet. The GitHub
  Action posts those as inline `suggestion` blocks on PRs — reviewers
  click "Apply suggestion" to one-click-fix.
- HIGH/CRITICAL findings come with a 3-4 sentence "adversarial
  scenario" narrative. Hover over a flagged aws_iam_role in VS Code
  and you get the Capital One breach story in plain English.
- Walks both `data "aws_iam_policy_document"` blocks AND inline
  `policy = jsonencode({...})` strings — closes a parity gap I
  hadn't seen any other scanner cover.
- LSP server (since 0.1.14) so VS Code shows diagnostics as you
  type, not on save.
- Deterministic 0–100 risk score with letter grade, in JSON output
  with a `scoring_version` for downstream gates.
- MITRE ATT&CK mapped on 48 rules; `--format mitre` groups findings
  by technique.

Stack is intentionally boring: stdlib-only Python core (~7,500 LoC),
optional python-hcl2 fast-path. Multi-arch Docker image. Composite
GitHub Action. Native .tftest.hcl regression tests via --gen-tests.
SARIF v2.1.0 + OSCAL Assessment Results JSON.

I built this as a Claude Code skill first; the standalone CLI fell
out of the same engine. The catalogue is one YAML per rule (200+
files) so PRs adding rules don't touch Python.

Demo against terragoat (intentionally vulnerable corpus):
https://github.com/ChrisAdkin8/tf-analyze/tree/main/reports

Happy to take feedback on the comparison table in the README — I've
tried to be honest about where tfsec / checkov / Prowler are better
or comparable.
```

## Submission timing

- **Best**: Tuesday or Wednesday, 8:00–9:30 ET (US East Coast morning).
- **Avoid**: Friday afternoons, weekends, US holidays.
- **Title rule**: HN strips "Show HN:" if you prefix manually but not the algorithm boost — keep the prefix.

## Engagement plan

Be available to respond for the first 4 hours. Top comments tend to
ask:

1. *"How does this compare to tfsec / checkov?"* — point at the README
   comparison table and the attack-graph differentiator.
2. *"Why Python and not Go?"* — stdlib-only choice was deliberate
   (no `pip install` for the core); `python-hcl2` is the optional
   fast-path. A Rust core is on the roadmap if perf becomes the gate.
3. *"What's the false-positive rate?"* — 134 negative ("clean") fixtures
   exist; tier-1 calibration was a deliberate Round 26 deliverable.
   Actively interested in real-world false-positive reports.
