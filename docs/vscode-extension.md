# VS Code Extension

The tf-analyze VS Code extension surfaces findings inline as you write
Terraform — squiggle underlines on affected lines, hover tooltips,
Quick Fix (⌘.) to insert fix_hcl, and a side-panel findings tree.

## Installation

**From source (development):**
```bash
cd vscode-extension
npm install
npm run compile
# Open VS Code, press F5 to launch the Extension Development Host
```

**From VSIX (production):**
```bash
cd vscode-extension
npm install
npm run package            # produces tf-analyze-0.1.0.vsix
code --install-extension tf-analyze-0.1.0.vsix
```

**From Marketplace (once published):**
```
ext install hashicorp.tf-analyze
```

## Requirements

- VS Code 1.85+
- Python 3.9+ on `$PATH`
- `detect.py` in the workspace (`scripts/detect.py`) or configured via
  `tf-analyze.scriptPath`

## Features

### Inline diagnostics

Every finding appears as a squiggle on the relevant source line:
- **Error** (red) — findings at or above `tf-analyze.failOn` (default: HIGH)
- **Warning** (yellow) — MEDIUM findings
- **Info** (blue) — LOW findings

### Hover tooltip

Hovering over a squiggle shows the finding ID, title, and urgency.

### Quick Fix (⌘. / Ctrl+.)

When a finding has a `fix_hcl` snippet, a Quick Fix action is available:
- **"Apply fix for SEC-AWS-EBS-001"** — inserts the canonical fix_hcl below
  the current line as a comment block to review and merge manually.
- **"View recommendation for SEC-AWS-EBS-001"** — opens a webview panel
  with the full recommendation, fix_hcl, disruption level, and source excerpt.

### Findings tree (Explorer panel)

The **tf-analyze Findings** panel in the Explorer sidebar shows all findings
grouped by section (security, robustness, ops, …). Click any finding to
jump to the source line.

### Status bar

The extension contributes two status-bar items, anchored bottom-left:

1. **Scan summary** — shows the current scan state and is clickable to run a fresh scan:
   - `⏳ tf-analyze scanning…` — scan in progress
   - `✓ tf-analyze: clean` — zero findings
   - `🛡 tf-analyze: 7 (C:1 H:2 M:4)` — summary by urgency
2. **Attack Graph shortcut** — `🛤️ Attack Graph`, sits immediately to the right of the scan summary. One click opens the internet → crown-jewels webview. Hidden in workspaces that contain no `.tf` files (so non-Terraform projects don't see a useless button).

Both items are wired to the same commands available from the Command Palette (`tf-analyze: Run Scan`, `tf-analyze: Show Attack Graph`) — the status-bar buttons are just the fast path.

### Auto-scan on save

When `tf-analyze.runOnSave` is `true` (default), the extension
automatically re-scans when any `.tf` file is saved.

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
| `tf-analyze: Show Attack Graph` | Open the attack-graph view (requires `--attack-graph`). |

## Architecture

The extension is a thin wrapper around `detect.py --format json`. It:

1. Spawns `python3 scripts/detect.py --target <workspace> --format json`
2. Parses the JSON array of findings (`id`, `file`, `line`, `urgency`, …)
3. Creates VS Code `Diagnostic` objects mapped to source positions
4. Registers a `CodeActionProvider` that generates Quick Fix actions for
   findings that have `fix_hcl`
5. Populates the `FindingsProvider` tree view

No network calls are made. All analysis is local.

## Extending

To add a new command or view, edit `src/extension.ts` and update
`contributes` in `package.json`. The `FindingsProvider` drives the tree;
the `TfAnalyzeCodeActionProvider` drives Quick Fix.
