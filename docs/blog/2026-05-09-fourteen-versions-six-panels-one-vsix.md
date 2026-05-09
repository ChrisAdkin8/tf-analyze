---
layout: default
title: "Fourteen versions, six panels, one VSIX"
date: 2026-05-09
permalink: /blog/2026-05-09-fourteen-versions-six-panels-one-vsix/
extension_version: 0.1.22
---

# Fourteen versions, six panels, one VSIX

*v0.1.7 → v0.1.22 of the [tf-analyze VS Code extension](https://github.com/ChrisAdkin8/tf-analyze/tree/main/vscode-extension), in chronological order.*

This is the unedited story of getting one VS Code extension from "displays a button" to "renders an attack graph, runs a real LSP, bundles its own engine, and survives bad input". Every bug below is real and has a corresponding line in [`vscode-extension/CHANGELOG.md`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/vscode-extension/CHANGELOG.md). The point isn't that the extension was broken — it's that **shipping a multi-surface tool means each release exposes the next layer's bug**, and the only way to find out is to run end-to-end.

## The setup

The tf-analyze engine is one ~7,500-line Python file (`scripts/detect.py`) that runs eight different ways: a CLI, a Docker image, a GitHub Action, a pre-commit hook, an HCP Terraform run task, an LSP server, a Claude Code skill, and a VS Code extension. The VS Code extension is the most ambitious surface because it has to be both:

1. **A diagnostic surface** — squiggles, hover tooltips, Quick Fix code actions.
2. **A workflow surface** — attack graph, compliance reports, bulk remediation, baseline suppression.

By v0.1.7 the extension had inline diagnostics + Quick Fix + a tree view + a status-bar item. The journey below is everything that broke as we tried to make the *workflow surfaces* actually work.

## v0.1.7 — Status-bar Attack Graph shortcut

A second status-bar button next to the existing scan shield, opening the attack-graph webview. Hidden in workspaces with no `.tf` files (no point in a Terraform-only button on a Python project).

This release didn't break anything new. But adding the button meant **users actually clicked it** — and the panel rendered blank.

## v0.1.8 — Wrong JSON key, silent fallback, four error paths

Root cause: the webview read `data.attack_graph`, but the engine emits the graph at `data.graph`. The optional-chain fallback `data.attack_graph ?? graph` silently fell through to an empty placeholder. **Blank panel, no error.**

Lesson: silent fallbacks in webviews compound. We replaced the single try/catch (which swallowed exec errors, parse errors, and empty graphs alike) with four distinct error panels:

| Error panel says | What broke |
|---|---|
| `detect.py not found` | Resolver couldn't locate the engine |
| `detect.py failed` (exit > 1) | Scan crashed |
| `Could not parse detect.py output` | Engine printed non-JSON to stdout |
| `Empty attack graph` | Engine succeeded but produced nothing |

Loud failure beats a blank SVG every time.

## v0.1.9 — The synthetic INTERNET node

The empty-graph guard in 0.1.8 checked `nodes.length === 0`. But `build_attack_graph` always emits a synthetic `INTERNET` entry node, so a workspace with no `.tf` resources at the root produced `nodes.length === 1` — a single floating red dot. Users (rightly) called it empty.

Fix: ignore the synthetic node and require at least one edge. The dedicated help panel now surfaces the actual `--target` path and the three common causes (workspace-root mismatch, no internet entry point, only modules/providers/data sources at the root).

## v0.1.10 — `JSON.parse('')` was the diagnostic, not the bug

The error path in 0.1.8 triggered on `exit > 1`. But `detect.py` exits 1 both for "findings present" (expected) AND for "Python crashed with an unhandled exception" (catastrophic). The webview was treating any `exit ≤ 1` as success, falling through to `JSON.parse('')`, and rendering blank.

We tightened the trigger: empty/whitespace stdout regardless of exit code. The reproduction command line and stderr now show in the error panel.

**This is the inflection point of the whole arc.** Once the panel surfaced the actual command, the next two bugs became obvious in seconds.

## v0.1.11 — `python3 <directory>` doesn't work

The 0.1.10 panel showed:

```
Command: python3 /Users/.../tf-analyze/scripts --target …

stderr: can't find '__main__' module in '/Users/.../tf-analyze/scripts'
```

The `_resolveScriptPath` helper accepted any path that `fs.existsSync` returned true for — *including directories*. Users who set `tf-analyze.scriptPath` to the `scripts/` folder got `python3 <dir>`, which Python interprets as "run the package", and there's no `__main__.py`.

Fix: require `fs.statSync(p).isFile()`, treat a configured directory as "look for `detect.py` inside", and walk up to six parent directories of the workspace looking for `scripts/detect.py` (so opening a fixture as the workspace root just works).

## v0.1.12 — `node not found: undefined`

With the script path resolved correctly, we finally got JSON back from the engine. d3 immediately threw:

```
Uncaught Error: node not found: undefined
  at d3.v7.min.js
```

The engine emits edges as `{from, to, label}`. d3's `forceLink` reads `{source, target}` and resolves them via `.id(d => d.id)`. Without aliasing, d3 saw `source === undefined` on every link, looked up node ID `undefined`, and threw before any nodes rendered.

Two-line fix in the webview script. **This was the first release where the d3 rendering path actually ran end-to-end.** v0.1.8 fixed empty panels. v0.1.9 fixed an edge case of the empty panel. v0.1.10/0.1.11 fixed *script resolution*. None of them ever reached the rendering code that v0.1.12 fixed — every previous "fix" had short-circuited before d3 was given a chance to fail.

## v0.1.13 — HTML report panel + shared resolver

With the attack graph finally rendering, we added the HTML report panel (run `detect.py --format html` in a webview iframe) and pulled the script-path resolver out into `src/scriptResolver.ts`. The 0.1.8 changelog had flagged "unify the resolver across both surfaces" as a TODO; with two consumers, it was time.

## v0.1.14 — One commit, five new surfaces

A single release added:

- **LSP client** — `python3 detect.py --lsp` as a real JSON-RPC server. Real-time diagnostics + Quick Fix update on every keystroke.
- **Delta panel** — `--auto-compare` shows new / resolved / unchanged findings since the last scan.
- **Compliance panel** — `--format html --compliance --compliance-framework {cis,pci_dss,soc2,all}` with a framework picker.
- **MITRE ATT&CK view** — findings grouped by ATT&CK technique.
- **Baseline UI** — right-click a finding → suppress; writes to `<ws>/.tf-analyze-baseline.json`; runScan auto-pins `--baseline` when the file exists.

Status bar now reads "scan · graph · report · delta · compliance · remediate" left to right.

This release also surfaced **two engine bugs** that the new panels exercised for the first time:

- `_compliance_gap_report` raised `TypeError: '<' not supported between instances of 'str' and 'int'` because `_ctrl_sort_key` returned mixed `int`/`str` parts (control IDs like `1.2.3` vs `AC-2.a`). Fixed with `(sort_class, value)` tuple wrapping.
- `_handle_apply_fixes` raised `IsADirectoryError` because absent-resource findings carry the *target directory* in their `file` field, not a real path. Fixed by switching `path.exists()` to `path.is_file()`.

The compliance panel was the trigger to fix both.

## v0.1.15 — Bulk remediation + the test suite

`tf-analyze.remediate` opens a panel that runs `--apply-fixes dry-run`, renders the unified diff with syntax highlighting (additions green, deletions red, file headers gold), and only writes to disk after explicit confirmation. Originals saved as `<file>.bak`.

Same release added 22 tests (`node --test`):

- 11 baseline tests (suppress/unsuppress idempotency, distinct-key handling, corrupted-file recovery)
- 7 scriptResolver tests (file vs. directory, parent walk, configured-path fallbacks)
- 4 engine smoke tests that spawn `python3 detect.py` and confirm the IsADirectoryError + compliance regressions don't come back

The smoke tests skip gracefully when `python3` isn't on `$PATH` so contributors can run `npm test` without a full repo checkout.

## v0.1.16 — One missing icon, hard validation failure

```
Manifest validation error: Missing property icon
```

`tf-analyze.clearFindings` was wired into `view/title` `navigation` group but its command declaration had no `icon` field. The schema requires one for navigation buttons. The error had been latent for months; 0.1.15 made it loud by adding five more navigation buttons to the same toolbar — VS Code now validates the whole group together.

## v0.1.17 — Status-bar items vanished

After fixing 0.1.16, the user reported: **none of the status-bar icons are showing**.

`activationEvents` only listed `onLanguage:terraform` (fires when a `.tf` file becomes the active editor) and `onView:tfAnalyzeFindings` (fires when the Findings view is opened). If a fresh VS Code window opened a Terraform workspace and the user didn't immediately open a `.tf` file or the Findings view, the extension stayed dormant — `activate()` never ran and no `createStatusBarItem` calls happened.

Added `workspaceContains:**/*.tf` so the extension wakes up the moment VS Code finishes scanning a workspace with Terraform code in it.

## v0.1.18 — `.vscodeignore` ate the runtime dependency

```
command 'tf-analyze.showAttackGraph' not found
```

Every command unreachable. The 0.1.16 manifest fix had landed; the 0.1.17 activation-events fix had landed; the icons still didn't show. **What was different from 0.1.13?**

`.vscodeignore` had `node_modules/**`. 0.1.14 added `vscode-languageclient` as a runtime dep. The packaged `.vsix` shipped *without* the module on disk; `require('vscode-languageclient/node')` raised `MODULE_NOT_FOUND` at extension load time; the entire `extension.js` module failed to load; `activate()` never ran; every `commands.registerCommand` was unreachable.

The 0.1.16 ("Missing property icon") and 0.1.17 ("activation events") reports were **downstream symptoms of the same packaging bug** — VS Code happened to surface different parts of the failure depending on which contribution it was inspecting at the time. The activation-events fix in 0.1.17 was correct but irrelevant: even with the right events, the module that defines `activate()` couldn't load.

Removed `node_modules/**` from `.vscodeignore`. The published `.vsix` went from 280KB / 24 files to 734KB / 338 files — the extra weight is the language-client tree, all of which is required at runtime.

## v0.1.19 — Self-contained .vsix

Up to this point, the extension still required users to either clone the tf-analyze repo or set `tf-analyze.scriptPath`. That was the single biggest adoption blocker: a five-minute install became a "find this other GitHub repo" treasure hunt.

`scripts/bundle-engine.js` now copies the engine **and catalog** from the source repo into `vscode-extension/engine/{scripts,catalog}/` at build time. The bundled layout mirrors the source repo so `detect.py`'s default `--catalog` resolution (`Path(__file__).parent.parent / "catalog"`) finds the catalog automatically — no extension-side flag plumbing required.

`scriptResolver.resolveScriptPath()` checks the bundled location *first*, before the `tf-analyze.scriptPath` setting and any workspace fallbacks. **Self-containment is now a hard product requirement, not a current convenience.**

Same release dropped the `📄 Report` status-bar item — the HTML report and the Findings tree present the same data with different ergonomics, and toolbar real estate should be reserved for surfaces that give net-new information at a glance. Status bar is now five items.

## v0.1.20 — Version sync, codified

A no-op release. Every doc that quoted a `.vsix` filename pointed at 0.1.19; the next one was about to be 0.1.21; the `code --install-extension` command in three docs would copy-paste users to an artefact that no longer existed on the release page.

Added a "VS Code extension version sync" section to `CONTRIBUTING.md` listing the three live-version docs (`vscode-extension/README.md`, `docs/vscode-extension.md`, `README.md` integrations table) and the three categories of historical doc that must *not* be touched on a bump (`CHANGELOG.md` files, archived planning docs). Six-step bump checklist so reviewers can call out exactly which step was skipped.

## v0.1.21 — `crashed 5 times in 3 minutes`

```
The tf-analyze (LSP) server crashed 5 times in the last 3 minutes.
The server will not be restarted.
```

`scripts/detect.py:_run_lsp_server`'s main message loop had no `try/except` around individual message processing. Any uncaught Python exception inside a handler (`_scan_uri`, `detect_in_file`) propagated out and killed the entire server. VS Code restarted it; the same trigger killed it again; after five crashes `vscode-languageclient` gave up entirely.

Wrapped every handler in `try/except`. Tracebacks now go to stderr (visible in the extension's Output channel), the loop continues, and crashed requests get a JSON-RPC `Internal error` reply so the client doesn't hang on a missing response.

Also tightened the `textDocumentSync` capability to spec-compliant shape (`{openClose: true, change: 1, save: {includeText: false}}`) and added a `textDocument/didChange` handler for keystroke-level updates.

## v0.1.22 — `unrecognized arguments: --stdio`

The 0.1.21 hardening was correct but landed too late in the pipeline to help. Real root cause:

```
detect.py: error: unrecognized arguments: --stdio
Server process exited with code 2.
```

`vscode-languageclient` v9 injects `--stdio` into the spawned server's argv when `transport: TransportKind.stdio` is set on the `Executable` server options (verified in `node_modules/vscode-languageclient/lib/node/main.js` — three call sites do `args.push('--stdio')` under the stdio branch). detect.py's argparse rejected the unknown flag and exited 2 *before* `main()` could reach `_run_lsp_server`, so the try/except hardening from 0.1.21 never had the chance to run.

Added the five flags `vscode-languageclient` might inject as `argparse.SUPPRESS`-d no-ops:

```python
ap.add_argument("--stdio", action="store_true", default=False, help=argparse.SUPPRESS)
ap.add_argument("--node-ipc", action="store_true", default=False, help=argparse.SUPPRESS)
ap.add_argument("--socket", default=None, help=argparse.SUPPRESS)
ap.add_argument("--port", default=None, help=argparse.SUPPRESS)
ap.add_argument("--clientProcessId", default=None, help=argparse.SUPPRESS)
```

stdio is the only transport detect.py supports anyway, so silently accepting the hint is semantically correct.

## What I'd tell past me

Three lessons that would have saved hours:

1. **Silent fallbacks in webviews compound.** `?? defaultGraph`, `exit ≤ 1 = success`, `existsSync = usable` — each one hid the layer below it. The 0.1.10 diagnostic hardening was the single biggest force multiplier in this whole arc; once the panel surfaced the *actual* command line, the next two bugs (script-path, d3 alias) were fixable in five-minute turnarounds.

2. **When fixing an error-path bug, expect the next bug to surface.** Don't ship the fix and assume done — drive the happy path through to render. Half the bugs above were short-circuited by an earlier failure and only became visible once the earlier failure was patched.

3. **Bundling vs. cloning is an adoption cliff.** v0.1.18 fixed the `.vsix` packaging bug. But until v0.1.19 bundled the engine itself, every new user still had to clone a separate repo. The self-containment refactor was the single biggest adoption unlock, and it came later than it should have.

The extension is at v0.1.22 now. The next post on this arc will be when something else breaks.

---

[← back to blog index](../) · [tf-analyze on GitHub](https://github.com/ChrisAdkin8/tf-analyze)
