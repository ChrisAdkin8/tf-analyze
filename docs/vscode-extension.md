# VS Code Extension

The tf-analyze VS Code extension surfaces findings inline as you write
Terraform — squiggle underlines on affected lines, hover tooltips,
Quick Fix (⌘.) to insert fix_hcl, and a side-panel findings tree.

## Self-containment guarantee

**The extension is self-contained.** A fresh `code --install-extension
tf-analyze-X.Y.Z.vsix` works on any workspace out of the box: no
companion repository to clone, no `tf-analyze.scriptPath` setting to
configure, no `pip install` to run. The detection engine
(`scripts/bundle-engine.js` copies `detect.py` into the extension's
`engine/` directory at build time) ships inside the `.vsix` and
`scriptResolver.resolveScriptPath()` checks the bundled location
first, before any workspace fallbacks.

This is a **hard product requirement, not a current convenience.** Any
future runtime the extension needs — a different engine version, a
SAT solver, a static-analysis helper — must be bundled the same way.
The workspace-fallback paths in the resolver are *engine-developer
escape hatches only* (so contributors can run the extension via F5
against their working copy of `detect.py`), not user features.

## Installation

**From the `.vsix` (the only supported user path):**
```bash
code --install-extension tf-analyze-0.1.22.vsix
```

That's it. Open any Terraform workspace and the status-bar items
appear immediately.

**From source (engine developers only):**
```bash
cd vscode-extension
npm install
npm run bundle-engine       # copies ../scripts/detect.py into engine/
npm run compile
npm test                    # runs the 25-test suite (unit + engine smoke)
# Open VS Code, press F5 to launch the Extension Development Host
```

**From Marketplace (once published):**
```
ext install hashicorp.tf-analyze
```

## Requirements

- VS Code 1.85+
- Python 3.9+ on `$PATH` (the bundled `detect.py` uses Python stdlib only —
  no `pip install` step required)

## Features

### Inline diagnostics

Every finding appears as a squiggle on the relevant source line:
- **Error** (red) — findings at or above `tf-analyze.failOn` (default: HIGH)
- **Warning** (yellow) — MEDIUM findings
- **Info** (blue) — LOW findings

### Hover tooltip

Hovering over a squiggle shows the finding ID, title, and urgency.
The rule ID is a **clickable link** that opens the per-rule docs page
on the project's GitHub Pages site
(`https://chrisadkin8.github.io/tf-analyze/rules/<RULE-ID>.html`) with
the full explainer, "why it likely fired", remediation, verification,
adversarial scenario, and references (CIS / PCI-DSS / SOC 2 / MITRE
ATT&CK).

The same link appears in the **Problems pane** next to every
diagnostic and as a prominent **"📖 Open full rule documentation"**
button at the top of the recommendation webview.

### Quick Fix (⌘. / Ctrl+.)

When a finding has a `fix_hcl` snippet, a Quick Fix action is available:
- **"Apply fix for SEC-AWS-EBS-001"** — inserts the canonical fix_hcl below
  the current line as a comment block to review and merge manually.
- **"View recommendation for SEC-AWS-EBS-001"** — opens a webview panel
  with the full recommendation, fix_hcl, disruption level, source excerpt,
  and a "📖 Open full rule documentation" button linking to the per-rule
  docs page.

### Findings tree (Explorer panel)

The **tf-analyze Findings** panel in the Explorer sidebar shows all findings
grouped by section (security, robustness, ops, …). Click any finding to
jump to the source line.

### Status bar

The extension contributes five status-bar items, anchored bottom-left, reading "scan · graph · delta · compliance · remediate" left to right:

1. **🛡 tf-analyze (scan summary)** — current scan state, click to run a fresh scan.
   - `⏳ tf-analyze scanning…` — in progress
   - `✓ tf-analyze: clean` — zero findings
   - `🛡 tf-analyze: 7 (C:1 H:2 M:4)` — summary by urgency
2. **🛤 Attack Graph** — opens the internet → crown-jewels webview.
3. **🔀 Delta** — *Since last scan*. New / resolved / unchanged findings against the most recent prior JSON report.
4. **✅ Compliance** — Compliance gap report with framework picker (CIS / PCI DSS / SOC 2 / All).
5. **🪄 Remediate** — Bulk apply-fixes with diff preview. Two-stage flow: dry-run shows the unified diff, **Apply Fixes** rewrites files on disk and saves originals as `<file>.bak`.

All five are gated on the workspace containing at least one `.tf` file. Each is wired to the same command available from the Command Palette — the status bar is just the fast path.

The HTML report (`tf-analyze: Show Report`) intentionally does *not* have a status-bar entry — it overlaps semantically with the Findings tree (same data, different presentation), and toolbar real estate is reserved for surfaces that give net-new information at a glance. The command stays a click away in the Command Palette and the Findings tree-view title bar.

### Real-time diagnostics (LSP)

Since v0.1.14 the extension starts `python3 detect.py --lsp` as a JSON-RPC language server on activation. Diagnostics + Quick Fix update as you type, not only on save. The legacy exec-on-save path is still wired up as a fallback when the language server can't start (e.g. on systems without Python on `$PATH`).

The `tf-analyze: Run Scan` command remains exec-based — it covers the whole workspace, including files that aren't currently open in an editor. Open files get LSP coverage; the workspace-wide tree comes from the explicit scan.

### Baseline / suppression

Right-click any row in the **Findings** tree → **Suppress finding (add to baseline)** to write the (id, file, line, resource) tuple to `<workspace>/.tf-analyze-baseline.json`. Subsequent scans automatically pick up the baseline file and suppress matching findings. **Unsuppress finding** reverses it; **Open Baseline File** loads the JSON in the editor for bulk edits.

### MITRE ATT&CK view

Run `tf-analyze: Show MITRE ATT&CK View` from the Command Palette to see findings grouped by ATT&CK technique (`T1078.004`, `T1530`, …). Useful when prepping a red-team report or correlating Terraform findings with broader detection coverage.

### Bulk remediation

The `🪄 Remediate` status-bar item (or the `tf-analyze: Remediate (preview & apply fixes)` command) opens a panel that:

1. Runs `detect.py --apply-fixes dry-run` to compute every fix the engine would make.
2. Renders the resulting unified diff with syntax highlighting (file headers gold, hunks grey, additions green, deletions red).
3. Asks for explicit confirmation before re-running with `--apply-fixes apply`, which writes the patched files to disk.

Originals are saved as `<file>.bak` alongside each patched file. The empty-state copy explains which fix kinds are eligible for bulk patching (`resource_missing_arg`, `resource_arg`, `hcl_attr`) — other patterns stay in the per-finding Quick Fix flow.

This is complementary to Quick Fix: the editor's `⌘.` action targets one finding at a time and inserts the snippet as a comment block; the remediation panel applies *every* fixable finding across the workspace in one shot, with an in-place rewrite.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `tf-analyze.scriptPath` | `` | Path to detect.py. Auto-detected if empty. |
| `tf-analyze.failOn` | `HIGH` | Minimum urgency level to render as Error. |
| `tf-analyze.runOnSave` | `true` | Re-scan on every .tf save. |
| `tf-analyze.section` | `` | Restrict to a section (empty = all). |
| `tf-analyze.extraArgs` | `[]` | Extra CLI flags (e.g. `["--compliance", "--compliance-framework", "pci_dss"]`). |

## Commands

| Command | Description |
|---------|-------------|
| `tf-analyze: Run Scan` | Run a full scan of the workspace. |
| `tf-analyze: Clear Findings` | Remove all diagnostics and reset the tree. |
| `tf-analyze: Show Attack Graph` | Open the attack-graph view (`--attack-graph`). |
| `tf-analyze: Show Report` | Open the HTML findings report inline. |
| `tf-analyze: Since Last Scan (Delta)` | Show new / resolved / unchanged findings vs. most recent prior report. |
| `tf-analyze: Show Compliance Report` | Compliance gap report with framework picker. |
| `tf-analyze: Show MITRE ATT&CK View` | Findings grouped by ATT&CK technique. |
| `tf-analyze: Suppress Finding` | Add the selected finding to the workspace baseline. |
| `tf-analyze: Unsuppress Finding` | Remove the selected finding from the baseline. |
| `tf-analyze: Open Baseline File` | Open `<ws>/.tf-analyze-baseline.json` in the editor. |
| `tf-analyze: Remediate (preview & apply fixes)` | Open the bulk-remediation panel (dry-run preview → apply with `.bak` backups). |

## Architecture

The extension drives `detect.py` through two complementary surfaces, both pointing at the **bundled engine** (`<extensionRoot>/engine/detect.py`, copied in by `scripts/bundle-engine.js` at build time):

1. **LSP (per-open-file, real-time).** On activation the extension spawns `python3 <bundled detect.py> --lsp` as a JSON-RPC language server. Diagnostics and code actions for `.tf` files currently open in an editor flow through `vscode-languageclient` and update on every change/save.
2. **Exec (whole-workspace, on-demand).** `tf-analyze: Run Scan` shells out to `python3 <bundled detect.py> --format json --target <ws>` once and uses the JSON to populate the **Findings** tree, the per-file diagnostic collection, and the status-bar summary. The same exec path also drives the Attack Graph, HTML Report, Delta, Compliance, MITRE, and Remediation panels — each panel runs its own engine invocation with the right `--format` and prints into a dedicated webview.

Both paths share `scriptResolver.resolveScriptPath()`, which always tries the bundled engine first. Workspace-relative fallbacks exist only to support the engine-development F5 loop and are *not* documented as a user feature — see the **Self-containment guarantee** section.

The runScan exec path also auto-detects `<workspace>/.tf-analyze-baseline.json` and adds `--baseline <path>` when present, so the baseline UI's writes take effect on the very next scan.

No network calls are made. All analysis is local.

## Extending

To add a new command or view, edit `src/extension.ts` and update
`contributes` in `package.json`. The `FindingsProvider` drives the tree;
the `TfAnalyzeCodeActionProvider` drives Quick Fix.

## Troubleshooting

### The Attack Graph panel opens but is blank

Multiple distinct failure modes have been collapsed into this symptom
across releases. Upgrade to v0.1.12+ and the webview will surface a
dedicated error panel for each class instead of rendering a silent
empty SVG. The displayed error tells you which case you've hit:

| Error panel says | Fixed in | What to check |
|---|---|---|
| **detect.py not found** | 0.1.8 / 0.1.19 | Should not happen on a properly-built `.vsix` — the engine is bundled inside the extension as of 0.1.19. If you see this, the install is corrupted or the extension was packaged without running `npm run bundle-engine` (check `<extensionRoot>/engine/detect.py` exists). For engine developers running via F5: set `tf-analyze.scriptPath` to your working copy, or rely on the workspace-relative / parent-walk fallbacks. |
| **detect.py failed** (exit > 1) | 0.1.8 | The scan crashed. The panel shows stderr — usually a syntax error in your HCL or a missing Python dependency. |
| **detect.py exited without printing JSON** | 0.1.10 | Python raised an unhandled exception (exit 1, empty stdout). The panel now shows the captured stderr and the exact reproduction command. The most common cause was the script-path setting pointing at the `scripts/` directory, which produced `can't find '__main__' module in '…/scripts'` — fixed in 0.1.11. |
| **Could not parse detect.py output** | 0.1.8 | The script printed non-JSON to stdout (often a Python warning leaking through). Run the same command at the terminal and inspect. |
| **Empty attack graph** | 0.1.9 | The workspace has no resources the graph engine recognises, or no resource is internet-reachable (no entry point → no path). Try `fixtures/attack_graph_demo/` from the tf-analyze repo as your workspace — that produces 8 nodes / 5 edges. |
| Webview shows `Uncaught Error: node not found: undefined` in DevTools | 0.1.12 | The engine emits edges as `{from, to}` but `d3.forceLink` reads `{source, target}`. Earlier builds passed the edges through unmodified, so any workspace with rendered edges crashed inside d3 before drawing. Upgrade. |

### Critical-path edges aren't red

Fixed in v0.1.8 — the webview was checking the wrong field. Upgrade.

### Findings panel shows but Quick Fix is greyed out

Quick Fix is only offered for findings whose catalogue rule has a
`fix_hcl` field (currently 100% of catalogue rules ship one, so this
should always be available for built-in rules). Custom `CUSTOM-*`
rules without `fix_hcl` won't show the Quick Fix action — that's by
design; add `fix_hcl` to the rule YAML.

### Status bar shows `🛡 tf-analyze: undefined`

Fixed in v0.1.6 — extension was reading legacy lowercase keys
(`summary.critical/.high/.medium`) but the engine emits counts under
`summary.counts` with uppercase severity keys. Upgrade.
