# Sample reports

Curated example reports produced by `detect.py` against the
[`examples/terragoat/`](../examples/terragoat) intentionally-vulnerable
corpus. Both formats are committed for the same scope so consumers can
see the JSON contract and a reader-friendly markdown render side-by-side.

| Scope | Markdown | JSON | Findings | Score |
|-------|----------|------|----------|-------|
| AWS   | [`tf-analysis-aws-2026-05-08.md`](tf-analysis-aws-2026-05-08.md)     | [`tf-analysis-aws-2026-05-08.json`](tf-analysis-aws-2026-05-08.json)     | 119 | 0 (F) |
| GCP   | [`tf-analysis-gcp-2026-05-08.md`](tf-analysis-gcp-2026-05-08.md)     | [`tf-analysis-gcp-2026-05-08.json`](tf-analysis-gcp-2026-05-08.json)     |  83 | 0 (F) |
| Azure | [`tf-analysis-azure-2026-05-08.md`](tf-analysis-azure-2026-05-08.md) | [`tf-analysis-azure-2026-05-08.json`](tf-analysis-azure-2026-05-08.json) |  90 | 0 (F) |
| All three clouds | [`tf-analysis-all-2026-05-08.md`](tf-analysis-all-2026-05-08.md) | [`tf-analysis-all-2026-05-08.json`](tf-analysis-all-2026-05-08.json) | 292 | 0 (F) |

> Score 0 (F) is **expected** — terragoat is a deliberately broken
> corpus. The reports demonstrate the tool's output, not the health of
> real infrastructure.

## What each report contains

### Markdown report (`*.md`)

A curated executive view rendered from the JSON, with sections for:

- **Risk score** — score, grade, urgency-bucketed counts (live `summary` block)
- **Executive summary** — finding totals, urgency breakdown
- **CRITICAL / HIGH findings** — first 15 per tier as scannable tables
- **MITRE ATT&CK coverage** — findings grouped by technique with rule examples
- **Attack graph** — node/edge counts, crown jewels, critical path
- **Top suggested fixes** — 5 highest-urgency findings with `fix_hcl` snippets
- **Reproduce** — the exact `detect.py` command that produced the report

### JSON report (`*.json`)

Raw `--format json --attack-graph` output. Top-level keys:

- `summary` — score, grade, counts, scoring_version, formula
- `findings` — enriched findings (urgency, title, narrative, mitre, fix_hcl, fix_disruption, recommendation)
- `graph` — attack-graph nodes + edges + critical path

This is the canonical machine-readable shape consumed by:

- `--compare prior.json` (delta tracking)
- `--baseline prior.json` (ratcheting)
- The web demo (`demo/`)
- The HCP Terraform Run Task callback payload

## Regenerating

```sh
python3 scripts/gen_sample_reports.py
# Regenerates with today's date by default.

python3 scripts/gen_sample_reports.py --date 2026-06-01
# Or pin to a specific date for release artefacts.
```

The generator runs `detect.py --target examples/terragoat/<scope>
--format json --attack-graph` for each of `aws` / `gcp` / `azure` /
`all`, then renders curated markdown from the JSON.

## Why the four scopes?

| Scope | Showcases |
|-------|-----------|
| `aws` | IAM-policy rules, RDS, S3, CloudTrail, SSRF/IMDS, ECS, Cognito |
| `gcp` | GKE hardening, Cloud SQL, IAM project-level grants, KMS, public buckets, firewall openings |
| `azure` | Key Vault network ACLs, SQL TDE, NSG flow logs, AKS hardening, Storage account public access |
| `all`  | Full corpus — exercises cross-cloud rules, full attack-graph build, MITRE coverage matrix |

Each cloud-specific report keeps the rule context narrow enough to read
end-to-end; the `all`-scope report shows what a real multi-cloud audit
output looks like at scale (292 findings, 35 crown jewels, 12 entry
points).
