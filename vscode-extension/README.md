![tf-analyze in action — Terraform security and stack analysis directly in your editor](assets/hero.png)

# tf-analyze for VS Code

> **Terraform security & stack analysis — directly in your editor.**
> Real-time inline findings, one-click bulk remediation, attack graph, compliance reports, and more — all from a single self-contained extension.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![VS Code](https://img.shields.io/badge/VS%20Code-1.85+-007ACC.svg?logo=visualstudiocode)](https://code.visualstudio.com/)
[![Terraform](https://img.shields.io/badge/Terraform-HCL-7B42BC.svg?logo=terraform)](https://www.terraform.io/)

---

## ✨ What it does

Brings the **`tf-analyze`** detection engine (215 catalogue rules across AWS, GCP, and Azure) into VS Code. The `.vsix` is **self-contained** — it bundles its own copy of the engine and rule catalogue, so installing the extension is the only step. No companion repo to clone, no `tf-analyze.scriptPath` setting to configure, no `pip install` to run.

| | |
|---|---|
| ⚡ **Real-time diagnostics** | An LSP server runs in the background and updates squiggles as you type. Hover for the full explanation, severity, and CIS mapping. |
| 🔧 **Quick Fix actions** | When a rule has an auto-fix, hit `⌘.` / `Ctrl+.` to apply it without leaving the editor. |
| 🪄 **Bulk remediation** | One-click status-bar shortcut previews every fix the engine would make as a syntax-highlighted unified diff. Apply once confirmed; originals saved as `<file>.bak`. |
| 🌳 **Findings tree** | A dedicated Activity Bar panel groups every finding by section, with one click to jump to the source. Right-click a finding to suppress it (writes to a workspace baseline). |
| 🕸️ **Attack-graph view** | Visualise IAM, network, and KMS reachability between resources in an interactive webview — spot lateral-movement paths at a glance. |
| ✅ **Compliance reports** | Built-in compliance gap report against CIS, PCI DSS, SOC 2 (or all combined), with a framework picker dropdown. |
| 🔀 **Since-last-scan delta** | New / resolved / unchanged findings against the most recent prior scan — turns each save into visible progress. |
| 🎯 **MITRE ATT&CK view** | Findings grouped by ATT&CK technique for red-team reports and threat-modeling reviews. |
| 📦 **Module Reuse Advisor** | Surfaces directories whose resource cluster matches a popular Terraform Registry module (AWS VPC, GCP network, Azure AKS, …) — INFO-tier, never gates CI. Each match shows an ROI estimate (`~85 lines saved (87%)`) so the suggestion is actionable. |
| 🏷️ **Status-bar score badge** | The shield item shows `tf-analyze: 82 (B) · 7 findings (C:1 H:2 M:4)` — the same score+grade the engine emits in JSON, recoloured red/orange/amber/blue/green by grade so an F repo visibly reds out without forcing the eye to read the digits. |
| 🔗 **`vscode://` deep links** | Four-verb URI handler routes `vscode://tfanalyze.tf-analyze/rule/<RULE-ID>`, `…/scan?target=<path>`, `…/explain?id=<RULE-ID>&file=<path>&line=<n>`, and `…/suppress?id=<RULE-ID>[&file=<path>&line=<n>]`. Strict regex validators on every verb refuse path-traversal / null-byte / outside-workspace inputs. Powers the docs site's "📂 Open in VS Code" + "📝 Suppress in workspace" buttons and one-click baseline-add from PR comments. |

---

## 🚀 Quickstart

### 1. Install

```bash
code --install-extension tf-analyze-0.1.56.vsix
```

That's it. The extension ships with everything it needs.

### 2. Open a Terraform workspace

You'll immediately see six status-bar shortcuts in the bottom-left:

```
🛡 tf-analyze: 82 (B) · 7 findings   🛤 Attack Graph   🔀 Delta   ✅ Compliance   🪄 Remediate   📦 Module Reuse
```

The shield item shows the workspace's score and letter grade, recoloured by grade (green for A, blue for B, amber for C, orange for D, red for F). Open any `.tf` file and squiggles appear on offending lines as you type. Click the shield to open the **Findings** tree, or any other status-bar item to jump straight into that surface.

---

## 🎛️ Commands

All commands are available via the Command Palette (`⌘⇧P` / `Ctrl+Shift+P`):

| Command | What it does |
|---|---|
| `tf-analyze: Run Scan` | Force a fresh whole-workspace scan. |
| `tf-analyze: Clear Findings` | Wipe diagnostics and the Findings tree. |
| `tf-analyze: Show Attack Graph` | Open the interactive resource-graph webview. |
| `tf-analyze: Show Report` | Open the urgency-grouped HTML findings report. |
| `tf-analyze: Since Last Scan (Delta)` | Show new / resolved / unchanged findings vs. last scan. |
| `tf-analyze: Show Compliance Report` | Compliance gap report with CIS / PCI DSS / SOC 2 / OWASP IaC / All picker. |
| `tf-analyze: Show MITRE ATT&CK View` | Findings grouped by ATT&CK technique. |
| `tf-analyze: Remediate (preview & apply fixes)` | Bulk apply-fixes panel — dry-run preview, then apply with `.bak` backups. |
| `tf-analyze: Show Module Reuse Advisor` | Surface directories whose resource cluster matches a community module on the Terraform Registry. INFO-tier — never gates CI. |
| `tf-analyze: Explain Rule (by ID)` | Open the rule explainer panel for a catalogue ID. Same panel opens automatically when a `vscode://tfanalyze.tf-analyze/rule/<RULE-ID>` link is clicked from the docs site, or when an `.../explain?id=<RULE-ID>&file=<path>&line=<n>` link is followed (the latter also navigates the editor to the offending location). |
| `tf-analyze: Suppress Finding` | Right-click a tree row to add it to the workspace baseline. |
| `tf-analyze: Unsuppress Finding` | Reverse a suppression. |
| `tf-analyze: Open Baseline File` | Open `<workspace>/.tf-analyze-baseline.json` for bulk edits. |

The scan, attack-graph, delta, compliance, remediate, and module-reuse commands also appear as status-bar shortcuts at the bottom-left and as title-bar buttons on the Findings view.

---

## ⚙️ Settings

Configure under **Settings → Extensions → tf-analyze**, or in `settings.json`:

| Setting | Type | Default | Purpose |
|---|---|---|---|
| `tf-analyze.scriptPath` | `string` | `""` | **Engine-developer escape hatch only.** Path to a custom `detect.py` to run instead of the bundled engine. End users should leave this empty. |
| `tf-analyze.failOn` | `enum` | `HIGH` | Minimum urgency to surface as an editor **error** (vs. warning/info). One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `tf-analyze.runOnSave` | `boolean` | `true` | Re-scan automatically when a `.tf` file is saved. (LSP coexists — when active, the on-save exec is skipped to avoid double-writing diagnostics.) |
| `tf-analyze.section` | `enum` | `""` | Restrict to one catalogue section: `security`, `robustness`, `ops`, `module`, `stack`, `style`. Empty = all. |
| `tf-analyze.extraArgs` | `string[]` | `[]` | Extra flags forwarded to `detect.py` (e.g. `["--compliance-framework", "pci_dss"]`). |

### Example: scope to security findings only, fail at `MEDIUM`

```jsonc
{
  "tf-analyze.section": "security",
  "tf-analyze.failOn": "MEDIUM",
  "tf-analyze.runOnSave": true
}
```

---

## 📋 Requirements

- **VS Code** `1.85.0` or later
- **Python** `3.9+` on `$PATH` — used to run the bundled engine. Stdlib only; **no `pip install` step required.**

The detection engine itself (`detect.py`) and the 215-entry rule catalogue ship inside the `.vsix`. You do **not** need to clone the [tf-analyze repo](https://github.com/ChrisAdkin8/tf-analyze) or install anything from PyPI.

---

## 🐛 Troubleshooting

<details>
<summary><b>The extension activates but I see no findings.</b></summary>

- Check the **Output** panel → **tf-analyze** channel. It logs the resolved `detect.py` path (should be inside the extension's bundled `engine/scripts/`) and the exact CLI invocation.
- If the channel reports an LSP startup failure, the extension falls back to exec-on-save — saves should still produce findings.
- Confirm the bundled engine works standalone:

  ```bash
  python3 ~/.vscode/extensions/tfanalyze.tf-analyze-*/engine/scripts/detect.py \
    --target /path/to/your/terraform --format text
  ```
</details>

<details>
<summary><b>Status-bar items aren't visible.</b></summary>

The six status-bar items (scan, graph, delta, compliance, remediate, module-reuse) only appear in workspaces that contain at least one `.tf` file. The extension activates on `workspaceContains:**/*.tf`, `onLanguage:terraform`, or `onView:tfAnalyzeFindings`.
</details>

<details>
<summary><b>Quick Fix isn't offered for a finding.</b></summary>

Not every rule has an auto-fix. Rules with `fix_hcl` support get Quick Fix; others link to the catalogue entry with a manual remediation note. For bulk patching across the workspace, use the **🪄 Remediate** status-bar item — its preview/apply flow covers every `resource_missing_arg`, `resource_arg`, and `hcl_attr` pattern in the catalogue.
</details>

<details>
<summary><b>The attack-graph view is empty.</b></summary>

The graph runs against the **first workspace folder**. The most common cause of an empty graph is that your `.tf` files live in a subfolder, not at the workspace root.

The empty-graph panel prints the exact path it scanned. If that path doesn't contain `resource` blocks, either:

- Open the subfolder containing your Terraform as the workspace root, **or**
- Add it as an additional folder via **File → Add Folder to Workspace…**

Other causes:

- **No internet entry point.** The graph starts from public LBs, public S3, security groups with `0.0.0.0/0`, etc., and walks to crown jewels (RDS, KMS, Secrets). With no entry point, there's no path to draw.
- **Only modules/providers/data sources at the root.** The engine builds nodes from `resource` blocks; `module` calls don't expand. Open the module's own folder.

Quick demo: clone [tf-analyze](https://github.com/ChrisAdkin8/tf-analyze) and open `fixtures/attack_graph_demo/` as your workspace — it produces 8 nodes and 5 edges.
</details>

<details>
<summary><b>I want to point the extension at a custom engine version.</b></summary>

This is an engine-developer scenario only. Set `tf-analyze.scriptPath` to your custom `detect.py`. End users should leave the setting blank — the bundled engine is intentionally the default and the `.vsix` ships with everything it needs.
</details>

---

## 🔗 Links

- 📖 **Source**: [github.com/ChrisAdkin8/tf-analyze](https://github.com/ChrisAdkin8/tf-analyze)
- 🐞 **Issues**: [GitHub Issues](https://github.com/ChrisAdkin8/tf-analyze/issues)
- 📜 **License**: Apache 2.0 — see [`LICENSE`](./LICENSE)
- 📄 **Full release notes**: [CHANGELOG.md](./CHANGELOG.md)

---

<sub>Self-contained `.vsix`. 217 rules · AWS · GCP · Azure · stdlib-only Python. Built with the `tf-analyze` Claude Code skill.</sub>
