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

- **text** — opt-in via `--blast-radius` (avoids cluttering CI logs).
- **json** — top-level `blast_radius` block + per-finding + per-node.
  Always emitted with `--attack-graph`. No flag gating: downstream
  consumers should be the ones who decide to use it.
- **sarif** — `properties.blastRadius` on each result. GitHub Code
  Scanning surfaces it in the result-detail panel; ranking/filtering
  by integer property is a built-in capability.
- **html** — table appended to the Attack Graph tab. Heat-coloured
  cells (pale yellow → red) so the eye lands on the highest-risk
  resources. Crown-jewel / internet-reachable chips for context.
- **pr-summary** — *future*: callout block after the score banner
  flagging findings whose `blast_radius > some_threshold`. Worth
  doing when the surface launches publicly.

### Public web scanner (`tfanalyze.com/scan/<owner>/<repo>`)

The HTML permalink at `/scan/<owner>/<repo>` should grow a "Blast
radius" section between the score banner and the findings table.
Render the same shape as the engine HTML report. **Pending: 30-min
follow-up** — `_render_public_report` in `demo/app.py` reads the
same JSON; just thread `result.get("blast_radius", [])` into a
small HTML fragment.

### Paste-and-scan demo (`tfanalyze.com/`)

- New "🌊 Blast radius — what one apply could touch" panel above
  module-reuse in the findings column. Top-5 horizontal-bar chart
  (max-relative width). **Shipped.**
- Attack-graph node circles scale with `blast_radius`: leaf nodes
  stay at base size, high-blast nodes grow up to +6px. SRE eye
  follows the bigger circles. **Shipped.**

### VS Code extension

*Future, separate release.* Recommended shape:

- New "🌊 Blast radius" tree view in the activity bar (priority
  between Findings and Attack Graph, ~85). Tree rooted at the highest-
  blast resource; expand to see the resources it would cascade to.
- Status bar segment when the workspace has any resource with
  `blast_radius >= 5`: `⚠ blast: aws_vpc.main → 12 downstream`.
- The bundled engine already emits the data — extension only needs
  to read `data.blast_radius` and `data.graph.nodes[i].blast_radius`.
  Estimate: 1 day of TypeScript + a CHANGELOG entry on the
  extension side.

### MCP server (`integrations/mcp-server/`)

*Future.* Add a new tool:

```
blast_radius_report(path: str, top_n: int = 10) -> dict
```

Returns the `blast_radius` block as a hardened dict (envelope
metadata, `_treat_as: data`). Useful for the
*"what is the riskiest single change?"* MCP prompt — the LLM gets
a deterministic answer without re-deriving the DAG.

### LSP server (`scripts/_lsp.py`)

*Future.* Currently diagnostic urgency tracks rule `default_urgency`.
Recommended uplift:

```
effective_urgency = max(rule.default_urgency, urgency_from_blast(blast))
where urgency_from_blast: 0 → unchanged; 1–4 → no uplift;
                          5–9 → +1 tier; 10+ → +2 tiers.
```

A HIGH finding on `aws_vpc.main` (blast=12) becomes CRITICAL in the
editor; the same rule on a leaf bucket stays HIGH. Lets editors
surface "this is the one to fix first" without the user reading the
attack-graph view. ~50 LoC change in `_lsp.py`.

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
