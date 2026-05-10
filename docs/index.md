---
layout: default
title: tf-analyze
---

# tf-analyze

Static + plan-time Terraform analysis with attack-graph prioritisation, MITRE ATT&CK mapping, and one-click PR fix suggestions. **Drop into CI in under 5 minutes.**

`tf-analyze` runs as a Claude Code skill, a standalone Python CLI, a GitHub Action, a Docker container, a pre-commit hook, an LSP server, a VS Code extension, an HCP Terraform Run Task, an [MCP server](https://github.com/ChrisAdkin8/tf-analyze/tree/main/integrations/mcp-server) for any AI agent (Cursor, Claude Desktop, Continue.dev, …), and a [native Terraform provider](https://github.com/ChrisAdkin8/tf-analyze/tree/main/terraform-provider) (`data "tfanalyze_scan"`). **Same engine, ten surfaces.**

## Read

- 📄 [**Project README**](https://github.com/ChrisAdkin8/tf-analyze#readme) — quickstart, feature matrix, the "why another scanner" pitch.
- 📚 [**Rule reference**](rules/) — auto-generated docs page per catalogue rule (217 pages, sortable by section/urgency in the index). Each page lists CIS / PCI-DSS / SOC 2 / OWASP IaC / MITRE references, every sibling in the same family (e.g. `SEC-AWS-IAM-001` links to `-002` and `-003`), and ships "📂 Open in VS Code" + "📝 Suppress in workspace" deep-link buttons.
- 🧩 [**VS Code extension**](vscode-extension.md) — installation, the six status-bar surfaces (scan with score+grade badge, attack graph, delta, compliance, remediate, module reuse), four-verb `vscode://` URI handler, troubleshooting matrix.
- ⚙️ [**CLI reference**](cli.md) — every flag, every output format, generated from `argparse` so it never drifts.
- 🛰️ [**LSP server**](lsp.md) — using `detect.py --lsp` from any LSP-aware editor.
- 🪝 [**Pre-commit hook**](pre-commit.md) — block PRs at commit time.
- 🏃 [**HCP Terraform Run Task**](run-task.md) — pre-apply gate inside HCP.
- 🧪 [**Custom rules**](custom-rules.md) — author your own `CUSTOM-*` catalogue entries.
- ⚖️ [**Severity calibration**](severity-calibration.md) — methodology behind `default_urgency` and the deterministic risk-score formula.

## Posts

- 📝 [**Blog index**](blog/) — design notes, debugging tours, release retrospectives.

## Source

- 🔗 [github.com/ChrisAdkin8/tf-analyze](https://github.com/ChrisAdkin8/tf-analyze)
- 🐞 [Issues](https://github.com/ChrisAdkin8/tf-analyze/issues)
- 📜 [Apache 2.0 licence](https://github.com/ChrisAdkin8/tf-analyze/blob/main/LICENSE)
