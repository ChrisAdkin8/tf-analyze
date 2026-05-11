---
title: Blast radius — "what could one terraform apply destroy?"
---

# Blast radius

> Shipped: **R30.17** (`scripts/_blast_radius.py`). Answers the SRE
> question that no other IaC scanner answers from static analysis.

## The premise

PR-review-shaped scanners (tfsec, checkov, trivy) tell you what is
insecure today. **They don't tell you what a single `terraform apply`
might destroy.** The SRE / oncall persona asks a different question:

> *If I run `terraform apply` after this PR, which downstream resources
> get touched — replaced, destroyed, or planned-changed?*

The answer falls out for free from the attack-graph DAG the engine
already builds. The same edges (`aws_vpc → aws_subnet` because the
subnet references `vpc.id`) describe both *compromise propagation*
(security framing) and *destroy propagation* (operability framing).
A BFS from each node counting distinct downstream nodes gives the
answer.

## What the engine emits

`tf-analyze --target . --attack-graph --format json` now includes:

```json
{
  "summary": { ... },
  "findings": [
    {
      "id": "SEC-AWS-S3-001",
      "resource": "aws_s3_bucket.data",
      "blast_radius": 0,
      ...
    },
    {
      "id": "SEC-AWS-SG-001",
      "resource": "aws_security_group.web",
      "blast_radius": 7,
      ...
    }
  ],
  "graph": {
    "nodes": [{ "id": "aws_vpc.main", "blast_radius": 12, ... }, ...]
  },
  "blast_radius": [
    {
      "resource": "aws_vpc.main",
      "type": "network",
      "file": "vpc.tf", "line": 12,
      "blast_radius": 12,
      "is_crown_jewel": false,
      "internet_reachable": false
    },
    ...
  ]
}
```

Three places the value lands:

1. **Per-finding** (`f.blast_radius`) — what would change if *this
   specific finding's resource* gets touched. Drives "fix the high-blast
   ones first" prioritisation.
2. **Per-node** (`graph.nodes[i].blast_radius`) — every node in the
   attack graph carries it. UIs scale node radius / colour by this.
3. **Top-N** (`output.blast_radius`) — pre-sorted list of the most
   dangerous resources to touch. Filtered: synthetic INTERNET node
   excluded; zero-blast leaves excluded; deterministic tie-breaking
   on resource id for byte-identical output across runs.

The block is only emitted when `--attack-graph` was passed (the
computation reuses that DAG; cheapness is a feature).

## The new flag

```sh
tf-analyze --target . --attack-graph --blast-radius
```

`--blast-radius` adds the dedicated text-format table after the
attack-graph mermaid block:

```
## Attack Graph
... (mermaid) ...

## Blast radius

Resources whose destruction/recreation would cascade to the most
downstream dependents. Treat these as high-care-on-apply.

  Resource                                         Downstream  Flags
  aws_vpc.main                                              12  -
  aws_subnet.public                                          7  -
  aws_security_group.web                                     6  inet
  aws_iam_role.lambda                                        4  -
  ...
```

JSON / SARIF / HTML output always carry the block when
`--attack-graph` ran — no separate flag needed for those formats.

## Companion rule: ROB-COUNTNAME-001

> *Resource external name embeds `count.index` — renumber-risk on apply.*

Catches the most pernicious version of "what a typo could destroy":

```hcl
resource "aws_instance" "web" {
  count = 3
  ami   = "ami-..."
  tags  = { Name = "web-${count.index}" }
}
```

Decrementing `count` from 3 to 2 destroys `aws_instance.web[2]`. Because
the external `Name` tag embeds the positional index, Terraform can't
even rebuild "web-2" on a different slot — the apply *will* destroy
real infrastructure. The rule fires on 16 name-like attributes:
`name`, `bucket`, `identifier`, `hostname`, `db_name`, `instance_name`,
`cluster_identifier`, `function_name`, `topic_name`, `queue_name`,
`table_name`, `role_name`, `user_name`, `repository_name`, `key_name`,
plus the `Name` tag (case-insensitive).

Fix: migrate to `for_each` with stable string keys.

## Existing coverage that already addresses adjacent concerns

| Concern | Already shipped |
|---|---|
| `prevent_destroy` missing on stateful resources | `ROB-AWS-LIFECYCLE-001`, `ROB-AZURE-LIFECYCLE-001`, `ROB-GCP-LIFECYCLE-001` cover 18 stateful types (RDS, S3, ElastiCache, Spanner, Cloud SQL, GCS, Compute Disk, Key Vault, MSSQL/MySQL/PostgreSQL, Azure Storage). |
| `force_destroy = true` on S3 / GCS buckets | `ROB-AWS-LIFECYCLE-002`, `ROB-GCP-LIFECYCLE-002`. |
| Unguarded `resource[0]` references to count-conditional resources | `ROB-COUNTREF-001` (companion to the new rule — same family, complementary direction). |
| Mixed backend types across root modules (S3 vs. GCS vs. local) | `ROB-BACKEND-001` (`kind: backend_inconsistency`). |
| S3 backend missing DynamoDB lock table | `ROB-AWS-BACKEND-001`. |

The drift-related ignore-changes overuse rules (`ROB-DRIFT-001/002/003`)
land in the same family but answer a different question — "is the team
silently hiding drift?" rather than "what would apply destroy?".

## Integration surfaces — how blast radius should reach each persona

The data is computed once. How it surfaces depends on what each
integration's user is trying to do.

### CLI (`text`, `json`, `sarif`, `html`, `pr-summary`)

- **text** ✅ — opt-in via `--blast-radius` (avoids cluttering CI logs).
- **json** ✅ — top-level `blast_radius` block + per-finding + per-node.
  Always emitted with `--attack-graph`. No flag gating: downstream
  consumers should be the ones who decide to use it.
- **sarif** ✅ — `properties.blastRadius` on each result. GitHub Code
  Scanning surfaces it in the result-detail panel; ranking/filtering
  by integer property is a built-in capability.
- **html** ✅ — table appended to the Attack Graph tab. Heat-coloured
  cells (pale yellow → red) so the eye lands on the highest-risk
  resources. Crown-jewel / internet-reachable chips for context.
- **pr-summary** ✅ — *Shipped in R30.18.* "🌊 High blast radius —
  review on-call impact" callout block lists findings whose
  `blast_radius ≥ 5` (same threshold as the LSP uplift). Resource
  address + downstream count + rule-docs link; SRE persona lands on
  exactly the section they care about even when the PR has 50+ findings.

### Public web scanner (`tfanalyze.com/scan/<owner>/<repo>`)

✅ *Shipped in R30.18.* The HTML permalink at `/scan/<owner>/<repo>`
now renders a "🌊 Blast radius — what one `terraform apply` could
touch" section between the top-fixes block and the run-locally CTA.
Heat-bar visualisation + crown-jewel / internet-reachable chips,
same shape as the engine HTML report.

### Paste-and-scan demo (`tfanalyze.com/`)

- New "🌊 Blast radius — what one apply could touch" panel above
  module-reuse in the findings column. Top-5 horizontal-bar chart
  (max-relative width). **Shipped.**
- Attack-graph node circles scale with `blast_radius`: leaf nodes
  stay at base size, high-blast nodes grow up to +6px. SRE eye
  follows the bigger circles. **Shipped.**

### VS Code extension

✅ *Shipped in v0.1.42 (R30.18).* Five surfaces, all derived from the
engine's blast-radius JSON:

- **🌊 Blast Radius tree view** in the activity bar — top-N
  high-blast resources, expandable to show downstream dependents
  (capped at 25 per parent to stay readable). Click jumps to the
  declaration line. See [`vscode-extension/src/blastRadiusView.ts`](../vscode-extension/src/blastRadiusView.ts).
- **Status-bar `🌊 N high-blast` chip** — visible only when at least
  one resource crosses the high-blast threshold (≥5). Click opens
  the tree view. Colour-coded amber at 1–2 / red at 3+.
- **CodeLens above resource declarations** — inline
  `🌊 12 downstream — destroying this would touch 12 other resources`
  appears above any `resource "..."` block whose blast is ≥3.
  See [`vscode-extension/src/blastRadiusLens.ts`](../vscode-extension/src/blastRadiusLens.ts).
- **Diagnostic hover enrichment** — messages append `🌊 blast: N`
  when the resource has non-zero downstream count.
- **Diagnostic severity uplift** — a HIGH finding on a leaf S3 stays
  HIGH; a MEDIUM on a 12-downstream VPC bumps to ERROR. The squiggle
  colour reflects operational impact, not just rule urgency.
  Thresholds match the LSP and PR-summary in `scripts/_lsp.py`
  (≥5 = +1 tier, ≥10 = +2 tiers, capped at ERROR).

### MCP server (`integrations/mcp-server/`)

✅ *Shipped in R30.18.* New `blast_radius_report(path, top_n=10)`
tool. Runs the engine with `--attack-graph`, extracts the top-N block,
wraps in the standard `_envelope_dict` (`_kind: blast-radius`,
`_treat_as: data`). Useful for the *"what is the riskiest single
change?"* MCP prompt — the LLM gets a deterministic answer without
re-deriving the DAG.

### LSP server (`scripts/_lsp.py`)

✅ *Shipped in R30.18.* `findings_to_diagnostics` now reads
`f.blast_radius` and applies a severity uplift:

```
effective_severity = base
if blast >= 5:  effective_severity -= 1
if blast >= 10: effective_severity -= 2     (capped at Error)
```

Also appends `🌊 blast: N` to the message text so the hover tooltip
carries the operational signal alongside the rule text. Skips
entirely when the field is absent or zero — LSP works identically
whether the engine was invoked with `--attack-graph` or not.

### Badge service (`tfanalyze.com/badge/...`)

No change. The badge is intentionally a single score+grade; blast
radius is decoration that doesn't compress to one number.

### GitHub Action / HCP Run Task / Terraform provider

These integrations consume the engine's JSON unchanged — they pick
up `blast_radius` automatically. The Run Task already returns the
full JSON to the workspace policy; HCP UI will render it as a
generic key.

## Why this matters strategically

The virality strategy doc (`docs/launch/virality-plan.md`) frames
the moat as *"answers questions other scanners don't ask"*. Module
reuse advisor and attack-graph reasoning were the first two. Blast
radius is the third — and it's the one that lands with **SRE / oncall
buyers** rather than appsec buyers. That's a distinct ICP, and one
that internal Platform Engineering teams (the buyers who actually
ratify a scanner choice for an org) tend to anchor on:

> *"It tells me what an apply would touch."*

That sentence is the headline. Build CTAs around it.
