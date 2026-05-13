---
layout: default
title: tf-analyze
---

# tf-analyze

Static + plan-time Terraform analysis with attack-graph prioritisation, MITRE ATT&CK mapping, and one-click PR fix suggestions. **Drop into CI in under 5 minutes.**

`tf-analyze` runs as a Claude Code skill, a standalone Python CLI, a GitHub Action, a Docker container, a pre-commit hook, an LSP server, a VS Code extension, an HCP Terraform Run Task, an MCP server for any AI agent (Cursor, Claude Desktop, Continue.dev, …), and a native Terraform provider (`data "tfanalyze_scan"`). **Same engine, ten surfaces.**

## Read

- 📄 [**Project README**](https://github.com/ChrisAdkin8/tf-analyze#readme) — quickstart, feature matrix, the "why another scanner" pitch.
- 📚 [**Rule reference**](rules/) — auto-generated docs page per catalogue rule (238 pages, sortable by section/urgency in the index). Each page lists CIS / PCI-DSS / SOC 2 / OWASP IaC / NIST CSF 2.0 / NIST SP 800-53 / CSA CCM v4 / SLSA / MITRE ATT&CK / CWE / D3FEND references, every sibling in the same family (e.g. `SEC-AWS-IAM-001` links to `-002` and `-003`), and ships "📂 Open in VS Code" + "📝 Suppress in workspace" deep-link buttons.

### Surfaces

- ⚙️ [**CLI reference**](cli.md) — every flag, every output format, generated from `argparse` so it never drifts.
- 🚀 [**GitHub Action**](github-action.md) — composite action with engine-rendered PR summary, inline `suggestion` blocks, SARIF upload, optional compliance gate.
- 🧩 [**VS Code extension**](vscode-extension.md) — installation, the seven status-bar surfaces (scan with score+grade badge, attack graph, delta, compliance, remediate, module reuse, blast radius), four-verb `vscode://` URI handler, troubleshooting matrix, R30.8-R30.12 hardening (120 s timeout, XSS-hardened webview, multi-root warning, URI gate).
- 🛰️ [**LSP server**](lsp.md) — using `detect.py --lsp` from any LSP-aware editor.
- 🪝 [**Pre-commit hook**](pre-commit.md) — block PRs at commit time.
- 🏃 [**HCP Terraform Run Task**](run-task.md) — pre-apply gate inside HCP.
- 🧠 [**MCP server**](mcp-server.md) — `scan_workspace` / `explain_rule` / `apply_fixes` / `attack_graph` / `compliance_report` / `blast_radius_report` tools for Claude Desktop, Cursor, Continue.dev, and other MCP-aware agents. Hardened against agent-side abuse (LLM01/05/06/10).
- 🪛 [**Terraform provider**](terraform-provider.md) — `data "tfanalyze_scan"` for gating `terraform apply` on a clean scan via `precondition` blocks, no external CI required.
- 🌊 [**Blast-radius analysis**](blast-radius.md) — `--blast-radius` answers the SRE question "what could one `terraform apply` destroy?" Per-finding + per-node + top-N rendered in CLI / PR summary / VS Code panel.

### Hosted surfaces — tfanalyze.com

- 🔗 [**Public scanner permalink**](https://tfanalyze.com/) — `tfanalyze.com/scan/<owner>/<repo>` resolves the GitHub repo's HEAD SHA, scans, and renders a styled HTML report with score banner, top findings (severity-ordered), top fixes, attack graph + module-reuse panels, and an Open Graph card so Slack/Twitter/HN preview cards show the score. JSON sibling at `.json`. Per-SHA cached.
- 📈 [**Trend dashboard**](https://tfanalyze.com/) — `tfanalyze.com/trend/<owner>/<repo>` walks the repo's git history (default 90 days), runs `--mode trend`, and renders a styled HTML page with per-commit findings sparkline + new/resolved/net velocity table + biggest-jump annotation + OG card. `?lookback=N` clamped 7-365 days.
- 🛡️ [**Score badge**](https://tfanalyze.com/) — `tfanalyze.com/badge/<owner>/<repo>.svg` is a shields.io-shape SVG embeddable in any README, reading the same per-SHA cache the permalink writes.
- 🤖 [**Auto-remediation PR bot**](github-action-bot.md) — Dependabot-style GitHub Action that runs on a schedule, applies non-disruptive `fix_hcl` patches, and opens a single PR per repo grouped by rule family. Safe-by-default (caps at `fix_disruption: none`). [Live demo repo](https://github.com/ChrisAdkin8/tf-analyze-bot-demo) with an open bot PR you can inspect.

### Authoring

- 🧪 [**Custom rules**](custom-rules.md) — author your own `CUSTOM-*` catalogue entries.
- ⚖️ [**Severity calibration**](severity-calibration.md) — methodology behind `default_urgency` and the deterministic risk-score formula.

## Posts

- 📝 [**Blog index**](blog/) — design notes, debugging tours, release retrospectives.

## Source

- 🔗 [github.com/ChrisAdkin8/tf-analyze](https://github.com/ChrisAdkin8/tf-analyze)
- 🐞 [Issues](https://github.com/ChrisAdkin8/tf-analyze/issues)
- 📜 [Apache 2.0 licence](https://github.com/ChrisAdkin8/tf-analyze/blob/main/LICENSE)
