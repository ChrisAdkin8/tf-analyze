<p align="center">
  <img src="assets/banner.svg" alt="tf-analyze" width="100%">
</p>

# tf-analyze

> Static + plan-time Terraform analysis with attack-graph prioritisation, MITRE ATT&CK mapping, and one-click PR fix suggestions. **Drop into CI in under 5 minutes.**

[![CI](https://github.com/ChrisAdkin8/tf-analyze/actions/workflows/ci.yml/badge.svg)](https://github.com/ChrisAdkin8/tf-analyze/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ChrisAdkin8/tf-analyze?include_prereleases&sort=semver)](https://github.com/ChrisAdkin8/tf-analyze/releases)
[![GitHub Marketplace](https://img.shields.io/badge/marketplace-tf--analyze-blue?logo=githubactions)](https://github.com/marketplace/actions/tf-analyze)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/tfanalyze.tf-analyze?label=vs%20code%20marketplace&logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze)
[![Open VSX](https://img.shields.io/open-vsx/v/tfanalyze/tf-analyze?label=open%20vsx&logo=eclipseide)](https://open-vsx.org/extension/tfanalyze/tf-analyze)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker)](https://github.com/ChrisAdkin8/tf-analyze/pkgs/container/tf-analyze)

![Python ≥3.10](https://img.shields.io/badge/python-%E2%89%A53.10-blue)
![Rules: 217](https://img.shields.io/badge/rules-217-brightgreen)
![fix_hcl: 100%](https://img.shields.io/badge/fix__hcl-100%25-brightgreen)
![MITRE / CWE / D3FEND](https://img.shields.io/badge/MITRE%20%2F%20CWE%20%2F%20D3FEND-69%25%20%2F%2053%25%20%2F%2040%25-brightgreen)
![Tests: 639](https://img.shields.io/badge/tests-639%20passing-brightgreen)
[![Rule docs](https://img.shields.io/badge/rule%20docs-217%20pages-brightgreen?logo=github)](https://chrisadkin8.github.io/tf-analyze/rules/)
![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue)

**[Quickstart](#quickstart) · [Why tf-analyze?](#why-tf-analyze) · [Features](#features) · [Documentation](#documentation) · [Adding a rule](#adding-a-rule) · [Repo layout](#repository-layout)**

`tf-analyze` runs as a Claude Code skill (`/tf-analyze`), as a standalone Python CLI, as a GitHub Action, in a Docker container, as a pre-commit hook, as an LSP server, as a VS Code extension, as an HCP Terraform Run Task, as an [MCP server](integrations/mcp-server/) for any AI agent (Cursor, Claude Desktop, Continue.dev, …), and as a [native Terraform provider](terraform-provider/) (`data "tfanalyze_scan"`). Same engine, ten surfaces.

---

## Quickstart

### 1. Docker — no Python install required

```sh
docker run --rm -v "$(pwd):/workspace" \
  ghcr.io/chrisadkin8/tf-analyze \
  --target /workspace --format html > report.html
open report.html
```

### 2. From source (Python ≥ 3.10)

```sh
git clone https://github.com/ChrisAdkin8/tf-analyze.git
cd tf-analyze
./install.sh                                          # installs as a Claude Code skill
pip install python-hcl2                               # optional fast-path (default-on if present)

python3 scripts/detect.py --target /path/to/terraform
python3 scripts/detect.py --target . --mode diff --fail-on HIGH --format sarif > out.sarif
python3 scripts/detect.py --list-rules
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-005
```

### 3. Inside Claude Code

```text
/tf-analyze                                # full audit, all areas
/tf-analyze focus:security mode:diff       # PR review
/tf-analyze mode:verify-fixed              # confirm prior fixes
```

### 4. VS Code extension

Live diagnostics, Quick Fix, attack graph, Module Reuse Advisor, and a `vscode://` URI handler — all from a self-contained `.vsix` (the engine and rule catalogue are bundled; no companion repo to clone).

```sh
# Marketplace (preferred, once the listing is live)
code --install-extension tfanalyze.tf-analyze

# Or from a downloaded .vsix (current path until the Marketplace listing publishes)
code --install-extension tf-analyze-0.1.37.vsix
```

Open any Terraform workspace and the six status-bar shortcuts appear bottom-left:

```
🛡 tf-analyze: 82 (B) · 7 findings   🛤 Attack Graph   🔀 Delta   ✅ Compliance   🪄 Remediate   📦 Module Reuse
```

To see the deeper panels render against rich input, open one of the showcase corpora in [`examples/`](examples/) — `examples/module-reuse-demo/` (📦) or `examples/attack-graph-demo/` (🛤). Full reference: [`docs/vscode-extension.md`](docs/vscode-extension.md).

### 5. GitHub Action

```yaml
- uses: ChrisAdkin8/tf-analyze@v1
  with:
    fail-on: HIGH
    post-pr-comment: true                # inline `suggestion` blocks on every PR
    compliance-framework: owasp_iac      # optional — adds a collapsible compliance gap report
    attack-graph: true                   # optional — embeds Mermaid attack graph in PR summary
    ref: v0.2.1                          # optional — pin the engine version (default: main)
```

See [`integrations/github-action.yml`](integrations/github-action.yml) for the full workflow with SARIF upload, engine-rendered PR summary (R28.1), and HTML artefact.

---

## Why tf-analyze?

A scanner is only as good as the actions it provokes. Where comparable tools stop at "here is a finding", `tf-analyze` ranks findings by attack-path centrality, ships an HCL fix, and surfaces the adversarial scenario on hover.

| | tf-analyze | tfsec | checkov | Prowler |
|---|---|---|---|---|
| Static HCL analysis | ✅ | ✅ | ✅ | ❌ (live) |
| Plan-time (`terraform show -json`) analysis | ✅ | ⚠️ partial | ✅ | ❌ |
| Built-in attack-path graph | ✅ | ❌ | ❌ | ❌ |
| Module Reuse Advisor with lines-saved ROI | ✅ | ❌ | ❌ | ❌ |
| Aggregate risk score + letter grade (A–F) | ✅ | ❌ | ❌ | ❌ |
| `fix_hcl` snippet on **every** rule | ✅ (100%) | ⚠️ partial | ⚠️ partial | n/a |
| Inline GitHub PR `suggestion` blocks | ✅ | ❌ | ❌ | n/a |
| MITRE ATT&CK mapping (technique + tactic-grouped output) | ✅ pinned to v17 | ❌ | ⚠️ partial | ⚠️ via plugin |
| MITRE D3FEND defensive-technique tagging | ✅ | ❌ | ❌ | ❌ |
| CWE taxonomy in SARIF output | ✅ | ❌ | ⚠️ partial | ❌ |
| OSCAL Assessment Results JSON output | ✅ | ❌ | ❌ | ❌ |
| OWASP IaC Cheat Sheet compliance mapping | ✅ | ❌ | ❌ | ❌ |
| Baseline ratcheting (`--baseline prior.json`) | ✅ | ⚠️ via filter | ✅ | ❌ |
| LSP server for IDE diagnostics | ✅ | ❌ | ❌ | ❌ |
| HCP Terraform Run Task integration | ✅ | ❌ | ❌ | ❌ |
| Native Terraform provider (`data "tfanalyze_scan"`) | ✅ | ❌ | ❌ | ❌ |
| MCP server for AI agents (Cursor / Claude Desktop / …) | ✅ | ❌ | ❌ | ❌ |
| YAML custom rules | ✅ | ✅ (Rego) | ✅ (Python+YAML) | ✅ (Python) |
| Stdlib-only core (optional fast-path) | ✅ | n/a | ❌ (pip) | ❌ (pip) |

> Comparison reflects features documented as of 2026-05; corrections welcome via issue.

### What makes tf-analyze different

1. **Attack-path graph + fix centrality** — BFS from internet-reachable resources to crown jewels. Findings on the critical path are promoted one urgency tier; fixes are ranked by how many crown jewels each one unblocks.
2. **`fix_hcl` on every rule, with disruption classification** — every finding ships an HCL snippet plus a `Non-disruptive` / `Plan required` / `Forces replacement` badge, so reviewers see operational impact before applying.
3. **Adversarial scenario narratives** — HIGH/CRITICAL findings come with a 3–4 sentence breach story (Capital One, Accenture, SolarWinds) to anchor severity in real outcomes.
4. **IAM policy analysis (HCL + inline JSON)** — ten dedicated rules walking both `data "aws_iam_policy_document"` blocks AND `policy = jsonencode({...})` strings on `aws_iam_policy` / `aws_iam_role_policy`. Covers wildcard action, wildcard resource, public principal, `iam:*` privesc, full-admin, NotAction.
5. **Baseline ratcheting** — adopt on a noisy legacy repo by snapshotting today's findings; only regressions block CI thereafter.
6. **Kubernetes + Helm coverage** — `kubernetes_namespace` Pod Security Admission, missing `kubernetes_network_policy`, `cluster-admin` `RoleBinding`s, plus `helm_release` overrides like `service.type=LoadBalancer` and `securityContext.privileged=true`.
7. **Provider-version-aware** — rules can declare `applies_when: { min_provider: { aws: "5.0" } }` so they self-skip on older provider versions instead of false-positiving.

---

## Features

### Detection

217 rules across six families. `--list-rules` enumerates them; `--explain RULE-ID` prints one in full.

| Family | Prefix | Focus |
|--------|--------|-------|
| Security | `SEC-*` | IAM over-grant, public exposure, hardcoded secrets, encryption gaps, exposed ports, MFA, key rotation |
| Robustness | `ROB-*` | Missing `prevent_destroy`, no state locking, unversioned providers, missing backups |
| Stack | `STK-*` | GKE/EKS/AKS hardening, RDS/CloudSQL config, Lambda DLQ/tracing, KMS rotation |
| Ops & Governance | `OPS-*`, `MOD-*`, `COST-*` | Tags/labels, unpinned modules, supply-chain refs, cost controls |
| Cross-resource | `INT-*`, `graph_check` | Intent–implementation gaps, KMS location parity, IAM breadth |
| Module reuse (advisory) | `MOD-REUSE-*` | Hand-rolled scaffolding that mirrors a popular Terraform Registry module — INFO tier, never gates CI. Pass `--show-info` to render |

**Per-cloud breakdown:** AWS 86 · GCP 43 · Azure 34 · Kubernetes/Helm 5 · cross-cloud 49.

### Execution modes

| Mode | Use case |
|------|----------|
| `static` (default) | Full source scan — no credentials needed |
| `diff` | Changed files only, auto-detected base branch — ideal for PR CI |
| `plan` | Static + resolved values from `terraform show -json` |
| `fleet` | Multi-repo scan; surfaces organisation-wide patterns |
| `trend` | Walk git history; new/resolved/net per commit |
| `pr-review` | Post inline GitHub PR review comments with one-click `suggestion` blocks |

### Output formats

| `--format` | What you get |
|------------|-------------|
| `text` (default) | One-line score header + findings list + attack-graph mermaid |
| `json` | Top-level `summary` block + findings; consumed by `--compare`, `--baseline` |
| `sarif` | SARIF v2.1.0 — line-level annotations on GitHub Code Scanning |
| `html` | Self-contained report with score banner, urgency badges, attack-graph SVG |
| `compliance` | CIS / PCI-DSS / SOC 2 / OWASP IaC PASS/FAIL per control (`--compliance-framework <name>`; `--oscal PATH` for OSCAL JSON). The `owasp_iac` framework maps the static-analysable items from the [OWASP IaC Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html). |
| `mitre` | Findings grouped by MITRE ATT&CK technique |
| `pr-summary` | GitHub-flavoured Markdown shape sized for PR descriptions / PR-bot comments — score banner, top-3 findings table (linked to docs site), top fix, collapsed Mermaid attack graph |

### Risk score

Every text, JSON, and HTML scan emits a deterministic 0–100 health score and letter grade A/B/B-/C/D/F. The score is the same number SKILL.md describes — `_RISK_WEIGHTS` and `_GRADE_TIERS` in `scripts/detect.py` are the single source of truth.

```
# tf-analyze: 82 (B) · 0 CRITICAL · 0 HIGH · 4 MEDIUM · 6 LOW · 0 INFO
```

```json
"summary": {
  "scoring_version": 1,
  "score": 82,
  "grade": "B",
  "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 4, "LOW": 6, "INFO": 0},
  "suppressed_count": 0,
  "formula": "max(0, 100 - sum(weight * count)); weights: CRITICAL=15, HIGH=7, MEDIUM=3, LOW=1, INFO=0; suppressed at half weight"
}
```

Suppressed and baseline-suppressed findings count at half weight (acknowledged, but the underlying risk still exists). INFO findings carry weight 0. The `scoring_version` field pins the formula — weight changes bump it so downstream gates can detect breakage. CI gates use `--fail-on LEVEL` (the urgency tier) rather than gating on the grade, intentionally — the grade is for trend visibility, not pass/fail.

### Useful modifiers

| Flag | Effect |
|------|--------|
| `--fail-on LEVEL` | Exit 1 if any finding at LEVEL or above (CI gate) |
| `--baseline prior.json` | Ratchet against a snapshot — only NEW findings affect exit code |
| `--attack-graph` | Build internet → crown-jewels graph; promote critical-path findings |
| `--show-fixes` | Render `fix_hcl` inline with disruption badges |
| `--gen-tests OUTDIR` | Emit native `.tftest.hcl` assertion files |
| `--apply-fixes dry-run\|apply` | Preview / write `fix_hcl` patches to source files |
| `--cache` | Incremental scan cache keyed on file + catalogue hash |
| `--diff-base REF` | Limit to `.tf` files changed since `REF` |
| `--no-hcl2` | Disable the python-hcl2 fast-path (env: `TF_ANALYZE_NO_HCL2=1`) |
| `--show-info` | Render INFO-tier findings (e.g. `MOD-REUSE-*` module-reuse advisories). Default off — INFO is counted in `summary.counts.INFO` but not displayed |

Full CLI reference: [`docs/cli.md`](docs/cli.md).

### Integrations

| | Path | Doc |
|---|------|-----|
| GitHub Action | [`integrations/github-action.yml`](integrations/github-action.yml) | SARIF + inline PR `suggestion` blocks + engine-rendered PR summary (`--format pr-summary`); optional `compliance-framework` / `attack-graph` / `show-info` inputs; pin via `ref` for reproducible CI |
| VS Code extension (v0.1.37) | [`vscode-extension/`](vscode-extension/) | [`docs/vscode-extension.md`](docs/vscode-extension.md) — self-contained `.vsix` (bundles its own engine), LSP-driven real-time diagnostics, Quick Fix, status-bar score+grade badge (`82 (B) · 7 findings`) with attack-graph / delta / compliance / remediate / module-reuse shortcuts, bulk apply-fixes with diff preview, baseline suppression UI, MITRE ATT&CK view, rule explainer + 4-verb `vscode://` deep-link handler (`/rule`, `/scan`, `/explain`, `/suppress`) |
| Score badge service | [`integrations/badge-service/`](integrations/badge-service/) | FastAPI app — embeddable SVG score badges per repo (`https://<host>/score/<owner>/<repo>.svg`); HMAC-signed `/ingest` endpoint accepts `detect.py --format json` output. Engineering complete; awaits `flyctl deploy`. |
| LSP server (`--lsp`) | `scripts/detect.py --lsp` | [`docs/lsp.md`](docs/lsp.md) |
| Docker image | `ghcr.io/chrisadkin8/tf-analyze` | Multi-arch `linux/amd64` + `linux/arm64`; bundles `python-hcl2` |
| Web demo | [`demo/`](demo/) | FastAPI + CodeMirror 6 + d3 attack graph |
| Pre-commit hook | [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml) | [`docs/pre-commit.md`](docs/pre-commit.md) |
| HCP Terraform Run Task | [`integrations/run-task/`](integrations/run-task/) | [`docs/run-task.md`](docs/run-task.md) |
| MCP server (Cursor / Claude Desktop / Continue / …) | [`integrations/mcp-server/`](integrations/mcp-server/) | FastMCP wrapper — `scan_workspace`, `explain_rule`, `apply_fixes`, `attack_graph`, `compliance_report` tools + `tfanalyze://catalogue` resource. stdio transport. Hardened against agent-side abuse: `TFA_REPO_ROOT` containment, `<tf-analyze-output>` envelope on every tool, finding/byte truncation caps. See [`integrations/mcp-server/README.md#hardening`](integrations/mcp-server/README.md#hardening). |
| Terraform provider | [`terraform-provider/`](terraform-provider/) | `data "tfanalyze_scan"` data source — gates `terraform plan`/`apply` on a clean scan via `precondition` blocks, no external CI required. |

---

## Screenshots

<table>
<tr>
<td><img src="docs/images/show-fixes.png" alt="Findings tab" /><br /><sub><strong>Findings tab</strong> — urgency-badged, collapsible, with adversarial narrative + suggested fix</sub></td>
<td><img src="docs/images/attack-graph-view.png" alt="Attack Graph tab" /><br /><sub><strong>Attack Graph</strong> — interactive force-directed SVG; critical path in red, crown jewels gold-bordered</sub></td>
</tr>
<tr>
<td><img src="docs/images/executive-view.png" alt="Executive View tab" /><br /><sub><strong>Executive View</strong> — findings reorganised into Entry Points / Lateral Movement / Crown Jewels / Blind Spots</sub></td>
<td><img src="docs/images/fix-priority.png" alt="Fix Priority tab" /><br /><sub><strong>Fix Priority</strong> — findings ranked by attack-path centrality; CRITICAL-PATH and INET-REACHABLE badges</sub></td>
</tr>
</table>

Additional screenshots: [compliance report](docs/images/compliance-report.png) · [fix-disruption badges](docs/images/fix-disruption.png) · [findings narrative panel](docs/images/findings-narrative.png).

---

## Documentation

| Topic | Doc |
|-------|-----|
| Full CLI reference (auto-generated) | [`docs/cli.md`](docs/cli.md) |
| Authoring custom `CUSTOM-*` rules | [`docs/custom-rules.md`](docs/custom-rules.md) |
| LSP server (Neovim, Emacs, Zed, coc.nvim) | [`docs/lsp.md`](docs/lsp.md) |
| HCP Terraform Run Task | [`docs/run-task.md`](docs/run-task.md) |
| Pre-commit hook | [`docs/pre-commit.md`](docs/pre-commit.md) |
| VS Code extension | [`docs/vscode-extension.md`](docs/vscode-extension.md) |
| Severity calibration methodology | [`docs/severity-calibration.md`](docs/severity-calibration.md) |
| Catalogue rule schema | [`catalog/README.md`](catalog/README.md) |
| Sample reports against terragoat | [`reports/README.md`](reports/README.md) |
| Skill prose (LLM-facing instructions) | [`SKILL.md`](SKILL.md) |
| Roadmap and TODO | [`TODO.md`](TODO.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |
| Blog (design notes, debugging tours, retros) | [`docs/blog/`](docs/blog/) |

When this repo is served via GitHub Pages (`Settings → Pages → Deploy from branch: main / docs`), the same content is reachable at `https://chrisadkin8.github.io/tf-analyze/` with the blog at `/blog/`.

---

## Adding a rule

```sh
python3 scripts/detect.py --new-rule SEC-MYDOMAIN-001
# wrote catalog/SEC-MYDOMAIN-001.yaml
# wrote fixtures/sec_mydomain_001/main.tf
```

Edit the two scaffolded files (TODO markers throughout), then run:

```sh
python3 -m pytest tests/test_fixtures.py -k sec_mydomain_001
python3 scripts/detect.py --explain SEC-MYDOMAIN-001
python3 scripts/detect.py --strict-catalog --target /tmp        # validates schema
```

Catalogue schema: [`catalog/README.md`](catalog/README.md). Custom-rule walkthrough: [`docs/custom-rules.md`](docs/custom-rules.md).

---

## Demo corpora — `examples/`

Three corpora that double as engine smoke tests and end-to-end demos for the surfaces that do graph reasoning across multiple resources. See [`examples/README.md`](examples/README.md) for the chooser.

| Corpus | Purpose |
|---|---|
| [`examples/terragoat/`](examples/terragoat/) | Three-cloud intentionally-vulnerable corpus modelled on Bridgecrew's [terragoat](https://github.com/bridgecrewio/terragoat). Triggers ~295 findings across SEC / ROB / STK / OPS / COST domains. Broadest coverage; the right pick for first-time users. |
| [`examples/module-reuse-demo/`](examples/module-reuse-demo/) | Five hand-rolled VPC/network/AKS clusters across AWS / GCP / Azure that match popular community modules + two negative cases. Exercises the **📦 Module Reuse** panel end-to-end with all three confidence-badge tiers visible. |
| [`examples/attack-graph-demo/`](examples/attack-graph-demo/) | Multi-tier AWS app: ALB → public EC2 → over-broad IAM role → S3 / Secrets / RDS. 19 nodes, 13 edges, 6 internet-reachable, 3 crown jewels. Exercises the **🛤 Attack Graph** panel and the d3 demo. |

```sh
python3 scripts/detect.py --target examples/terragoat --format html > demo.html
```

The single-rule fixtures under [`fixtures/`](fixtures/) (218 positive + 140 clean) complement these corpora — they isolate one rule each so a self-test failure points at exactly which detector broke. Drift on the demo corpora is gated by [`tests/test_examples_demos.py`](tests/test_examples_demos.py) so a catalogue change that shifts the documented finding counts fails the local pytest run instead of silently breaking the README screenshots.

---

## Repository layout

```
.
├── SKILL.md                    # Skill prose loaded as /tf-analyze in Claude Code
├── README.md                   # This file
├── CHANGELOG.md                # Per-round release notes
├── TODO.md                     # Roadmap and backlog
├── CONTRIBUTING.md
├── LICENSE                     # MPL-2.0
├── Dockerfile                  # ghcr.io/chrisadkin8/tf-analyze
├── pyproject.toml
├── install.sh                  # Symlinks repo into ~/.claude/skills/tf-analyze
├── .pre-commit-hooks.yaml      # pre-commit.com hook declaration
├── .github/workflows/          # CI (ci.yml, docker.yml)
├── catalog/                    # 217 rule definitions (one YAML per rule)
│   └── README.md               # Schema reference
├── fixtures/                   # 218 positive + 140 clean (negative) fixtures
├── examples/                   # Showcase corpora
│   ├── terragoat/              #   • Multi-cloud deliberately-vulnerable corpus
│   ├── module-reuse-demo/      #   • Module Reuse Advisor showcase (3 clouds)
│   └── attack-graph-demo/      #   • Multi-tier AWS app for the Attack Graph
├── scripts/
│   ├── detect.py               # Detection engine (~7,800 LoC; optional python-hcl2)
│   ├── self_test.py            # Walks fixtures/ vs catalog/, asserts expected IDs
│   ├── test_schema.py          # Catalogue schema regression tests
│   ├── stub-status.py          # Reports stale `status: stub` entries
│   ├── gen-cli-docs.py         # Regenerates docs/cli.md from argparse
│   ├── gen_clean_fixtures.py   # Auto-scaffolds clean fixtures from fix_hcl
│   └── apply_mitre.py          # Idempotent MITRE ATT&CK mapper
├── tests/                      # pytest suite (364 tests)
├── docs/                       # User-facing documentation
├── integrations/
│   ├── github-action.yml
│   ├── pre-commit-hook.yaml
│   └── run-task/               # HCP Terraform Run Task FastAPI server + Dockerfile
├── vscode-extension/           # TypeScript extension (Quick Fix, attack-graph webview)
├── demo/                       # FastAPI + d3 web demo (deployable to Fly.io)
├── reports/                    # Example report outputs (delta-tracking demos)
└── assets/                     # Banner, icon
```

The skill files (`SKILL.md`, `catalog/`, `scripts/`, `fixtures/`, `integrations/`) live at the repo root so `./install.sh` can `ln -s` the whole directory into `~/.claude/skills/tf-analyze` — no nested `skill/` subdir.

---

## Contributing & maintenance

Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow.

> **Versioning note for the VS Code extension:** every reference to a specific `tf-analyze-X.Y.Z.vsix` filename in user-facing documentation (this README's integrations table, `docs/vscode-extension.md`, `vscode-extension/README.md`) must always match the latest `vscode-extension/package.json#version`. Historical references inside changelogs and archived planning docs are exempt — they intentionally pin to the artefact that shipped at that version. Full rules and the version-bump checklist live in [`CONTRIBUTING.md` § VS Code extension version sync](CONTRIBUTING.md#vs-code-extension-version-sync).

Routine maintenance commands:

```sh
python3 -m pytest tests/                        # Full suite (~45s)
python3 scripts/test_schema.py                  # Catalogue schema regression
python3 scripts/stub-status.py --age 90d        # Find stale stubs
python3 scripts/gen-cli-docs.py                 # Regenerate docs/cli.md after argparse changes
python3 scripts/gen_clean_fixtures.py --write   # Auto-scaffold clean fixtures from fix_hcl
python3 scripts/gen_sample_reports.py           # Regenerate reports/*.{md,json} from terragoat
```

CI gate (`.github/workflows/ci.yml`) runs the pytest suite, the schema validator, the CLI-docs freshness check, and `stub-status.py --age 180d`. The Docker image is built and published on tag pushes via `.github/workflows/docker.yml`.

---

## Provenance

Built and exercised inside an HCP Vault + Consul + GKE platform engineering project; many catalogue rules trace to real audit findings on that infra. The skill is provider-agnostic in design and runs across AWS (86 rules), GCP (43 rules), Azure (34 rules), Kubernetes/Helm (5), and 49 cross-cloud rules — total 217 active. Full CIS Foundations Benchmark coverage on GCP; growing parity on AWS and Azure. Compliance output covers CIS, PCI-DSS v4.0, SOC 2 Trust Services Criteria, and the [OWASP IaC Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html).

---

## License

[Mozilla Public License 2.0](LICENSE). Catalogue rules and fixtures are released under the same licence to permit upstream contributions and downstream forks.
