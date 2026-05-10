# Changelog

All notable changes to the **tf-analyze** VS Code extension are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

---

## [0.1.38] — 2026-05-10

### Changed

- **Bundle pipeline now ships 8 sibling Python files (was 7).** R30.0.11 / Session E extracted the largest seam yet — the **entire** output-formatter block (SARIF v2.1 + HTML reports + MITRE + compliance + PR summary + `_ATTACK_NARRATIVES` data table) — out of `detect.py` into `_output.py` (1,619 LOC; 23 names). `vscode-extension/scripts/bundle-engine.js`'s `ENGINE_SIBLING_FILES` array now lists `['detect.py', '_mitre.py', '_versions.py', '_scoring.py', '_hcl.py', '_catalog.py', '_attack_graph.py', '_output.py']`. No user-visible behaviour change — `detect.py`'s re-export shim preserves every legacy name including the workhorses `to_sarif`, `to_html`, `_render_pr_summary`, `_render_compliance_html`, `_compliance_to_oscal` consumed by the extension's HTML report viewer + the GitHub Action's PR-comment block.

  Verified the bundle inside `tf-analyze-0.1.38.vsix`:

      extension/engine/scripts/_attack_graph.py (~30 KB)
      extension/engine/scripts/_catalog.py     (~16 KB)
      extension/engine/scripts/_hcl.py         (11.6 KB)
      extension/engine/scripts/_mitre.py        (6.3 KB)
      extension/engine/scripts/_output.py      (~60 KB)
      extension/engine/scripts/_scoring.py      (~4 KB)
      extension/engine/scripts/_versions.py     (8.0 KB)
      extension/engine/scripts/detect.py      (~238 KB)  ← below 250 KB for the first time since R12

  Cumulative across the 6 modularisation rounds: `detect.py` 8,441 → 5,528 LoC (**−2,913 / 34.5% reduction**); extracted modules now total 3,615 LoC of pure helpers across 7 files. The monolith is below 6,000 LoC for the first time since Round 12.

  Combined with R30.0.10's `--strict-catalog` smoke test fix, the build now actually fails on a bad YAML — both improvements landed in the same Markdown-week.

---

## [0.1.37] — 2026-05-10

### Changed

- **Bundle pipeline now ships 7 sibling Python files (was 6).** R30.0.9 / Session D extracted the largest seam yet — the entire attack-graph build + render block — out of `detect.py`: `_attack_graph.py` (812 LOC; 27 regex constants + 2 data maps + 7 functions including the 280-LoC `_render_graph_html` interactive force-directed SVG renderer). `vscode-extension/scripts/bundle-engine.js`'s `ENGINE_SIBLING_FILES` array now lists `['detect.py', '_mitre.py', '_versions.py', '_scoring.py', '_hcl.py', '_catalog.py', '_attack_graph.py']`; the `.vsix` ships all seven siblings at `engine/scripts/`. No user-visible behaviour change — `detect.py`'s re-export shim preserves every legacy name including the workhorses `build_attack_graph`, `graph_to_mermaid`, `_render_graph_html` consumed by the extension's `Show Attack Graph` command.

  Verified the bundle inside `tf-analyze-0.1.37.vsix`:

      extension/engine/scripts/_attack_graph.py (~30 KB)
      extension/engine/scripts/_catalog.py     (~16 KB)
      extension/engine/scripts/_hcl.py         (11.6 KB)
      extension/engine/scripts/_mitre.py        (6.3 KB)
      extension/engine/scripts/_scoring.py      (~4 KB)
      extension/engine/scripts/_versions.py     (8.0 KB)
      extension/engine/scripts/detect.py      (~298 KB)  ← shrank again

  Cumulative across the 5 modularisation rounds: `detect.py` 8,441 → 6,985 LoC (**−1,456**, 17.2% reduction); extracted modules now total 1,996 LoC of pure helpers across 6 files.

---

## [0.1.36] — 2026-05-10

### Changed

- **Bundle pipeline now ships 6 sibling Python files (was 5).** R30.0.8 / Session C extracted a fifth pure-function module out of `detect.py`: `_catalog.py` (catalogue lifecycle — YAML loading, schema validation with CWE / D3FEND / OWASP-IaC shape checks, `.tf-analyze.yaml` workspace config reader, `load_catalog` — 443 LOC). `vscode-extension/scripts/bundle-engine.js`'s `ENGINE_SIBLING_FILES` array now lists `['detect.py', '_mitre.py', '_versions.py', '_scoring.py', '_hcl.py', '_catalog.py']`; the `.vsix` ships all six siblings at `engine/scripts/`. No user-visible behaviour change — `detect.py`'s re-export shim preserves every legacy name including the workhorse `load_yaml`, `validate_catalog_entry`, and `load_catalog`.

  Verified the bundle inside `tf-analyze-0.1.36.vsix`:

      extension/engine/scripts/_catalog.py     (~16 KB)
      extension/engine/scripts/_hcl.py         (11.6 KB)
      extension/engine/scripts/_mitre.py        (6.3 KB)
      extension/engine/scripts/_scoring.py      (3.7 KB)
      extension/engine/scripts/_versions.py     (8.0 KB)
      extension/engine/scripts/detect.py      (~328 KB)  ← shrank again with Session C

  Cumulative across the 4 modularisation rounds: `detect.py` 8,441 → 7,669 LoC (−772); extracted modules now total 1,184 LoC of pure helpers.

---

## [0.1.35] — 2026-05-10

### Changed

- **Bundle pipeline now ships 5 sibling Python files (was 4).** R30.0.7 / Session B extracted a fourth pure-function module out of `detect.py`: `_hcl.py` (HCL primitives — text normalisation, comment scrubbing, top-level block extraction, attribute-presence checks, dynamic-block expansion — 320 LOC). `vscode-extension/scripts/bundle-engine.js`'s `ENGINE_SIBLING_FILES` array now lists `['detect.py', '_mitre.py', '_versions.py', '_scoring.py', '_hcl.py']`; the `.vsix` ships all five siblings at `engine/scripts/`. No user-visible behaviour change — `detect.py`'s re-export shim preserves every legacy private name.

  The smoke test the v0.1.33 work added did its job again: deliberately removing `_hcl.py` from the bundle output triggered `ModuleNotFoundError: No module named '_hcl'` plus the existing diagnostic ("This usually means a Python file detect.py imports as a sibling is missing from ENGINE_SIBLING_FILES above. Add it."). The verified bundle inside `tf-analyze-0.1.35.vsix`:

      extension/engine/scripts/_hcl.py          (11.6 KB)
      extension/engine/scripts/_mitre.py         (6.3 KB)
      extension/engine/scripts/_scoring.py       (3.7 KB)
      extension/engine/scripts/_versions.py      (8.0 KB)
      extension/engine/scripts/detect.py       (340 KB)  ← 357 KB → 340 KB after extraction

---

## [0.1.34] — 2026-05-10

### Changed

- **Bundle pipeline now ships 4 sibling Python files (was 2).** R30.0.6 extracted two more pure-function modules out of `detect.py`: `_versions.py` (provider-constraint helpers, 204 LOC) and `_scoring.py` (risk-score formula + grade tiers, 107 LOC). `vscode-extension/scripts/bundle-engine.js`'s `ENGINE_SIBLING_FILES` array now lists `['detect.py', '_mitre.py', '_versions.py', '_scoring.py']`; the `.vsix` ships all four siblings at `engine/scripts/`. No user-visible behaviour change — `detect.py`'s re-export shim preserves every legacy private name. The smoke test the v0.1.33 work added is doing exactly what it was designed to: deliberately removing `_versions.py` from the bundle output triggers a clean smoke-test failure with the correct diagnostic ("This usually means a Python file detect.py imports as a sibling is missing from ENGINE_SIBLING_FILES above. Add it.").

  Verified the bundle inside `tf-analyze-0.1.34.vsix`:

      extension/engine/scripts/_mitre.py        (6.3 KB)
      extension/engine/scripts/_scoring.py      (3.7 KB)
      extension/engine/scripts/_versions.py     (8.0 KB)
      extension/engine/scripts/detect.py      (357 KB)

---

## [0.1.33] — 2026-05-10

### Added

- **Bundle pipeline now smoke-tests the engine.** `scripts/bundle-engine.js` previously copied `detect.py` + `catalog/` into the extension's `engine/` directory and stopped there. As of 0.1.33 it also spawns `python3 engine/scripts/detect.py --list-rules` against the freshly-bundled engine and asserts a non-zero rule count. Catches three classes of build-time failure that would otherwise only surface at the user's first click:
  1. **Sibling-import miss.** When `detect.py` was refactored to `from _mitre import …`, the bundle script needed to know to copy `_mitre.py` too. The new `ENGINE_SIBLING_FILES` array lists every Python file `detect.py` imports as a sibling — adding a new file there is the only step required to ship a new helper module inside the `.vsix`.
  2. **Catalogue YAML parse error** introduced in this build.
  3. **Missing top-level Python dependency** (the engine is stdlib-only by contract; a regression here is otherwise silent in a `.vsix`).
  Set `PYTHON=...` if the build host needs a specific Python binary.
- **Bundled `_mitre.py` sibling module.** Engine refactor splits MITRE ATT&CK data + helpers into `scripts/_mitre.py`. The extension now ships both files at `engine/scripts/`. No behavioural change vs. 0.1.32; the file split lays groundwork for the broader detect.py modularisation.

### Internal (engine, consumed by extension)

- **SARIF v2.1 taxonomies + per-rule relationships.** SARIF output now includes a proper `taxonomies` array (CWE, MITRE-ATT&CK, MITRE-D3FEND, CIS) plus per-rule `relationships` references. GitHub Code Scanning consumers can semantically filter findings by taxon ("show me all CWE-732") instead of parsing flat tag strings. Flat tags are still emitted alongside for backward compat with consumers that haven't migrated. D3FEND relationships use the `incomparable` kind so consumers can distinguish "this rule indicates the named ATT&CK technique" from "this rule implements the named D3FEND defence".
- **ATT&CK drift CI gate.** `scripts/check_attack_drift.py` runs in CI and fails the build if any rule cites a `mitre:` technique missing from `_mitre.py`'s `MITRE_TECHNIQUE_INFO` table. Prevents silent decay as new techniques get added to the catalogue.

---

## [0.1.32] — 2026-05-10

### Changed

- **Re-release of the 0.1.31 fixes after iterating on the hero-image bug.** No new code or content beyond what 0.1.31 documents — the version bump exists because 0.1.31 went through three failed attempts at fixing the broken hero image (relative path, then HTML img wrapper, then markdown syntax) before the actual root cause was identified (vsce's `--baseImagesUrl` rewrite ignores `repository.directory` in monorepo packages). 0.1.32 is the clean release that ships the working state in one consistent .vsix; 0.1.31 should be considered superseded.

  Concretely, 0.1.32 carries:
  - `package`/`publish` npm scripts pin `--baseImagesUrl https://github.com/ChrisAdkin8/tf-analyze/raw/HEAD/vscode-extension`, so future builds via `npm run package` always emit a correct absolute hero URL
  - README hero is markdown `![]()` syntax (vsce rewrites this reliably); previous `<p align="center"><img>` block dropped
  - Hero URL inside the `.vsix`-bundled README resolves to HTTP 302 → 200 via github.com → raw.githubusercontent.com

  Verified with `unzip -p tf-analyze-0.1.32.vsix extension/README.md | head -1` showing the rewritten URL, then `curl -sIL` confirming reachability.

---

## [0.1.31] — 2026-05-10

### Added

- **MitrePanel: tactic-grouped output.** Engine's `--format mitre` now groups by ATT&CK tactic (Initial Access → … → Impact), with techniques as second-tier headers (`T1078.004 — Valid Accounts: Cloud Accounts`). MitrePanel was previously promoting `### Tnnnn` lines to `<h3>` chips, but the new shape uses `### <Tactic>` at the top level and indented `T<id> — <name>` lines underneath. Webview now renders three tiers: `<h1>` for the engine title, `<h2 class="tactic">` for tactic groups (gradient background, accent left-border), `<h3>` for techniques (chip + name + count). Legacy single-tier `### Tnnnn` output still renders correctly as a fallback.

- **RuleExplainerPanel: CWE + D3FEND chip rows.** `detect.py --explain <RULE-ID>` now emits four taxonomy header lines — CIS, MITRE ATT&CK, CWE, MITRE D3FEND — when the rule carries them. The panel promotes each to a coloured chip-row with click-through links to `cwe.mitre.org/data/definitions/<n>.html`, `attack.mitre.org/techniques/<id>/`, and `d3fend.mitre.org/technique/<id>/`. The four chip colours are distinct (CIS blue, MITRE purple, CWE amber, D3FEND green) so a finding's full threat-language footprint is visible at a glance.

- **Engine `--explain` upgrade (engine, not extension):** Previously only emitted CIS. Now emits MITRE ATT&CK, CWE, and D3FEND when present. The extension panel above consumes this.

### Fixed

- **Hero image now renders in the Extensions details panel.** Three layered bugs had to be peeled to find the actual root cause:

  1. **Earlier "fix" went the wrong direction.** A previous edit had changed the README's hero `<img>` from a relative path to an absolute `raw.githubusercontent.com/.../main/...` URL on the assumption that Marketplace required absolute URLs. That works for the Marketplace listing but breaks VS Code's installed-extension details panel on machines with restricted egress (corporate networks blocking `raw.githubusercontent.com` from VS Code's webview). Reverted to relative.

  2. **HTML `<img>` vs. markdown `![]()` aren't treated equivalently.** VS Code's README renderer handles markdown image syntax reliably; raw HTML `<img>` tags get less consistent treatment depending on the surrounding HTML block. Switched the hero from `<p align="center"><img src="..."></p>` to plain markdown `![alt](path)`.

  3. **The actual root cause: monorepo `directory:` mismatch in vsce's path rewriter.** `vsce` rewrites markdown image paths to absolute URLs at package time using the repo's `repository.url`, but it does **not** prepend the `repository.directory` field — even when one is set. With `directory: "vscode-extension"` and a relative `assets/hero.png`, vsce rewrote to `https://github.com/.../raw/HEAD/assets/hero.png` (404 — the actual file is at `.../raw/HEAD/vscode-extension/assets/hero.png`). Fixed by passing `--baseImagesUrl https://github.com/ChrisAdkin8/tf-analyze/raw/HEAD/vscode-extension` to both `vsce package` and `vsce publish`. The flag is now baked into the `package` and `publish` npm scripts so future builds don't regress. Verified: the `.vsix`-bundled README's image URL now resolves to HTTP 200 (after a single 302 redirect through GitHub).

---

## [0.1.30] — 2026-05-10

### Added

- **Compliance panel: OWASP IaC framework choice.** The framework picker (top of the Compliance panel) now offers `OWASP IaC` alongside `CIS / PCI DSS / SOC 2 / All`. Maps against the static-analysable items from the [OWASP Infrastructure-as-Code Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) — `Develop and Distribute / Secrets Detection`, `Resource Permission Minimization`, `Open Source Dependency Scanning`, `Cloud Asset Tagging`, `Comprehensive Logging Enablement`, etc. 49 catalogue rules carry the new mappings.

  Status-bar tooltip updated: `tf-analyze: open the compliance gap report (CIS / PCI DSS / SOC 2 / OWASP IaC)`.

### Internal

- No engine code changes inside the bundled VSIX — the framework picker just exposes the `--compliance-framework owasp_iac` choice the engine has supported since the matching engine release.

---

## [0.1.29] — 2026-05-09

### Added

- **Status-bar score+grade badge.** The shield item in the bottom-left now reads `🛡 tf-analyze: 82 (B) · 7 findings (C:1 H:2 M:4)` — the score+grade pair the engine emits in JSON, surfaced as the inherently shareable artefact. Badge text is recoloured by grade (`charts.green` for A, `charts.blue` for B, `charts.yellow` for C, `charts.orange` for D, `charts.red` for F) so an F repo visibly reds out without forcing the eye to read the digits. Colour resets on scan-start/error to avoid stale visual state.

- **`vscode://` URI handler — 4 verbs (was 1).** The single existing `/rule/<RULE-ID>` verb is joined by:

  - `/scan?target=<absolute path>` — kicks off a workspace scan; refused if the target is outside the active workspace.
  - `/explain?id=<RULE-ID>&file=<path>&line=<n>` — opens the rule explainer panel and (when file+line validate) navigates the editor to the offending location.
  - `/suppress?id=<RULE-ID>[&file=<path>&line=<n>]` — accepts both shapes. With file+line, performs per-finding baseline-add (PR-comment flow). With id only, performs workspace-wide rule ignore (writes to `.tf-analyze.yaml`'s `ignore_rules:` after a modal confirm). Powers the docs site's "📝 Suppress in workspace" button next to "📂 Open in VS Code".

  Every verb has a strict regex validator and refuses path-traversal / null-byte / outside-workspace inputs, surfacing a warning rather than silently no-opping (the v0.1.27 security pattern). Routing extracted into a pure dispatcher (`src/uriHandler.ts`) testable under `node --test` without spinning up VS Code.

- **Module Reuse panel — ROI rendering.** Each match row now includes a "Lines saved" column (`~85 lines (87%)`) and each rule section is preceded by a banner summarising savings across all matches (`~258 lines saved across 3 matches by adopting this module.`). Engine-side `roi` field on the finding is the source of truth; the panel only formats.

### Tests

- New `src/test/uriHandler.test.ts` — 24 `node:test` cases cover validators (`RULE_ID_RE`, `safePath`, `safeLine`), every verb's happy path, path-traversal/null-byte/outside-workspace rejection, both shapes of `/suppress`, and the unknown-path branch. Brings the extension's `node --test` suite from 35 → 59 cases.

### Internal

- Extracted URI dispatch into `src/uriHandler.ts`. The closure inside `vscode.window.registerUriHandler` now delegates to `dispatchUri(uri, handlers)`, with `handlers` injecting the side-effect surface (panel open, scan, suppress, warn, log). The pre-extraction shape was untestable under `node --test` because it directly touched `vscode.*`.
- New `appendIgnoreRule(ws, ruleId, out)` helper writes to `.tf-analyze.yaml`'s `ignore_rules:` block. Hand-edits the YAML rather than parse-and-rewriting so user comments and formatting survive; falls back to creating the block when absent.

---

## [0.1.28] — 2026-05-09

### Added
- **Walkthrough step 4 — "Try the showcase demos"** points first-run users at two new example corpora in the upstream repo: `examples/module-reuse-demo/` (5 dirs across 3 clouds, exercises the Module Reuse Advisor end-to-end with all three confidence-badge tiers visible) and `examples/attack-graph-demo/` (multi-tier AWS app, 19 nodes / 13 edges / 3 crown jewels, exercises the Attack Graph panel and the d3 graph view).

  Walkthrough completes when either `tf-analyze.showModuleReuse` or `tf-analyze.showAttackGraph` fires — gives users a concrete "click this button, see this output" loop instead of a generic "open a file" prompt.

  No engine or runtime change; this is pure onboarding copy. The demos themselves live in the upstream repo, not bundled into the `.vsix` (would have added ~20 KB of `.tf` content for content most users will look at once).

---

## [0.1.27] — 2026-05-09

### Added
- **Rule explainer panel + URI handler.** The docs site now ships an "📂 Open in VS Code" button on every rule page that targets the `vscode://tfanalyze.tf-analyze/rule/<RULE-ID>` URI scheme. Clicked in a browser, the OS routes to VS Code; the new `vscode.window.registerUriHandler` registration in `extension.ts` parses the path, regex-validates the rule ID against `/^\/rule\/([A-Z][A-Z0-9-]{2,63})$/`, and dispatches to `RuleExplainerPanel.createOrShow`.

  The panel itself (`src/ruleExplainer.ts`, ~120 LOC) shells out to `python3 detect.py --explain <RULE-ID>` against the bundled engine, then renders the plain-text output as a styled webview — `## Section` headings promoted to `<h2>`, the first-line `# RULE-ID — title` to `<h1>`, every cross-referenced rule ID linked to its docs page, and a one-click "Open full rule docs in browser" button that round-trips back to the site.

  Also exposed via the new `tf-analyze.explainRule` palette command — invoking it without an argument shows an `InputBox` with the same regex validator. The argument-passing form (`vscode.commands.executeCommand("tf-analyze.explainRule", "SEC-AWS-IAM-001")`) lets other extensions or tasks trigger the panel programmatically.

- **Security note.** The URI-handler path is the new attack surface most extensions don't think about. Mitigations:
  1. Strict regex on the URI path before any subprocess work — a malformed URI surfaces a warning, never silently no-ops.
  2. The rule ID is passed only as `--explain <ID>` argument to `cp.execFile` (not `cp.exec` or a shell pipe) so even if the regex were bypassed there'd be no shell-injection vector.
  3. The webview disables scripts (`enableScripts: false`) — escaped output only, no DOM access.

---

## [0.1.26] — 2026-05-09

### Added
- **Module Reuse Advisor panel** — a new entry in the activity-bar speed strip (`$(package) Module Reuse`) that surfaces directories whose resource cluster matches the shape of a popular community module on the Terraform Registry. Currently fingerprints `terraform-aws-modules/vpc/aws`, `terraform-google-modules/network/google`, and `Azure/aks/azurerm`.

  The panel runs `detect.py --show-info --format json`, filters findings to the `module-reuse` section, and groups hits by rule. Each hit shows the matched directory, anchor resource, registry-module link, confidence (low / medium / high — based on how far the cluster overshoots the supporting-types threshold), and a `match details` summary.

  Findings are INFO-tier so they never gate CI and don't affect the risk score (weight 0). Suppress per-rule via inline `# tf-analyze:disable=MOD-REUSE-…-001` or under `ignore_rules:` in `.tf-analyze.yaml`.

  Wired up via `src/moduleReusePanel.ts`, command `tf-analyze.showModuleReuse`, status-bar item priority 95 (sits to the right of Remediate), and a `view/title` toolbar entry on the Findings tree.

---

## [0.1.25] — 2026-05-09

### Fixed
- **Rule-ID links inside the Compliance and HTML-report panels were silent no-ops.** Both panels embed the engine's HTML output in an `<iframe srcdoc>`. VS Code webview iframes are sandboxed; clicking a regular `<a href="https://…">` does nothing — there's no parent context for `target="_blank"` to resolve to, and the iframe can't open URLs externally on its own. So `<a>` tags rendered fine but clicks went nowhere. (Note: 0.1.24's fix to use pretty URLs was correct — that change made the URLs *valid*; this one makes them *clickable*.)

  Fixed via a three-hop message bridge:

  1. **Iframe side** — a small click-interceptor script appended to the engine HTML before injection. Captures `<a>` clicks, calls `e.preventDefault()`, and forwards `{command: 'openLink', url}` to `window.parent.postMessage`. New helper `src/iframeBridge.ts:injectLinkInterceptor`.
  2. **Parent webview** — listens for `message` events from the iframe and re-posts them via `vscode.postMessage`. New helper `src/iframeBridge.ts:LINK_BRIDGE_PARENT_JS`.
  3. **Extension host** — both `compliancePanel.ts` and `htmlReport.ts` `onDidReceiveMessage` handlers gain an `openLink` case that calls `vscode.env.openExternal(vscode.Uri.parse(url))`.

  Same fix shipped in both panels because both have the same iframe-srcdoc pattern. The non-iframe panels (delta, MITRE, recommendation) are unaffected — VS Code's webview chrome handles their `<a>` tags directly via `enableCommandUris`-equivalent default behaviour.

### Added
- **`src/test/iframeBridge.test.ts`** (5 tests) — locks the contract on the bridge: interceptor injects before `</body>`, idempotent across refreshes, falls back to append when no body tag, parent-side script forwards to `vscode.postMessage`. If the bridge regresses, the silent-no-op behaviour comes back; the tests catch it locally.

---

## [0.1.24] — 2026-05-09

### Fixed
- **Every per-rule docs link from the extension was 404.** The links shipped in 0.1.23 pointed at `https://chrisadkin8.github.io/tf-analyze/rules/<RULE-ID>.html`, but GitHub Pages serves Jekyll-rendered pages at the pretty-URL form `…/rules/<RULE-ID>/` — the `.html` suffix returns 404. Verified with curl: `/rules/SEC-AWS-IAM-001.html` → 404, `/rules/SEC-AWS-IAM-001/` → 200.

  Affected every rule-ID rendering surface that landed in 0.1.23:
  - Diagnostic `code` target in the Problems pane and hover tooltip
  - "📖 Open full rule documentation" button in the recommendation webview
  - Delta panel rule IDs
  - MITRE ATT&CK panel rule IDs
  - Compliance panel (inherits engine HTML — engine constant fixed in lockstep)

  `ruleDocsUrl()` in `src/urls.ts` now returns `${RULE_DOCS_URL_BASE}${ruleId}/` instead of `${ruleId}.html`. The same change shipped in `scripts/detect.py:RULE_DOCS_URL_BASE` so engine output (compliance HTML, SARIF helpUri, Findings panel) matches.

  `src/test/urls.test.ts` updated to lock the pretty-URL form so future drift is caught locally rather than only at runtime against the live site.

---

## [0.1.23] — 2026-05-09

### Added
- **Every rule ID in the extension is now a clickable link to its docs page.** Five surfaces wired through the new `src/urls.ts` shared helper:
  1. **Diagnostic `code`** — VS Code's Problems pane and hover tooltip render the rule ID as a clickable link. Was a stale `github.com/example/...` placeholder; now points at `https://chrisadkin8.github.io/tf-analyze/rules/<RULE-ID>.html`.
  2. **Recommendation webview** — the panel that opens via "View recommendation" / `tf-analyze.openFinding` gains a prominent **"📖 Open full rule documentation →"** button styled with the urgency colour.
  3. **Delta panel** (`tf-analyze: Since Last Scan`) — rule IDs in the delta listing wrap in dotted-underline anchors that highlight on hover.
  4. **MITRE ATT&CK view** — rule IDs grouped under each technique are now anchors. Regex covers all 10 catalogue prefixes (`SEC`, `ROB`, `STK`, `OPS`, `MOD`, `COST`, `INT`, `CI`, `STYLE`, `CUSTOM`).
  5. **Compliance panel** — already linked through the engine's HTML output (which started emitting `<a>` anchors in the same release as the per-rule docs site).

- **`src/urls.ts`** — single source of truth: `RULE_DOCS_URL_BASE`, `ruleDocsUrl(id)`, `ruleAnchorHtml(id)`. All surfaces import from here so a future move to a custom domain (e.g. `tf-analyze.dev/rules/...`) is a one-line edit that ripples to every callsite. Mirrors the engine's `RULE_DOCS_URL_BASE` constant in `scripts/detect.py`.

- **`src/test/urls.test.ts`** — locks the URL contract: format string, all 10 prefix variants, anchor HTML structure (`target="_blank"` + `rel="noopener"` + `title="Open rule documentation"`). Drift between the extension's URL and the engine's becomes a test failure.

### Why this matters
Compliance failures get pasted into Slack threads, JIRA tickets, and runbook wikis. A clickable rule ID means a non-engineer auditor never has to clone the repo to find out what `SEC-AWS-IAM-002` actually means — they get plain English explanation, why it likely fired, and the remediation snippet directly.

---

## [0.1.22] — 2026-05-09

### Fixed
- **`detect.py: error: unrecognized arguments: --stdio` — actual root cause of the LSP crash loop reported against 0.1.21.** `vscode-languageclient` v9 injects `--stdio` (and depending on configuration, `--node-ipc`, `--socket`, `--port`, `--clientProcessId`) into the server's argv when `transport: TransportKind.stdio` is set on the `Executable` server options. detect.py's argparse refused the unknown flag and exited with code 2 *before* the engine could reach `_run_lsp_server`, so the loop-hardening landed in 0.1.21 never had a chance to help. Added the five injected flags to argparse as `argparse.SUPPRESS`-d no-ops; stdio is the default and only transport detect.py supports anyway, so accepting the hints is semantically correct. The 0.1.21 try/except hardening still matters — it'll catch any *runtime* exceptions once the engine is actually running.

---

## [0.1.21] — 2026-05-09

### Fixed
- **`The tf-analyze (LSP) server crashed 5 times in the last 3 minutes. The server will not be restarted.`** The LSP server's main message loop in `scripts/detect.py:_run_lsp_server` had no exception handler around individual message processing — any uncaught Python exception in `_scan_uri`, `detect_in_file`, or any of the per-method branches propagated out and killed the entire server. VS Code restarted it; the same trigger killed it again; after five crashes vscode-languageclient gave up entirely until the user reloaded the window. Wrapped each message handler in `try/except`: tracebacks now go to stderr (visible in the extension's `tf-analyze` Output channel), the loop continues, and requests that crashed get a JSON-RPC `Internal error` response so the client doesn't hang waiting for a reply that'll never arrive.
- **`textDocumentSync` capability shape was non-spec-compliant.** The server returned `{"openClose": true, "save": true}`, but the LSP spec requires `change` to be an integer (None=0, Full=1, Incremental=2) and `save` to be a `SaveOptions` object. Strict clients can refuse the capability and silently disable diagnostics. Now returns `{"openClose": true, "change": 1, "save": {"includeText": false}}` — Full-sync because we re-scan the whole file on every update anyway.
- **Added handler for `textDocument/didChange`** (re-using the same scan-and-publish path as `didOpen`/`didSave`). With `change: 1` advertised, clients send `didChange` on every keystroke; without a handler, the previous else-branch sent a `MethodNotFound` reply for what's actually a notification, polluting the protocol stream.

---

## [0.1.20] — 2026-05-09

### Changed
- **Version sync release.** No code changes. Bumps the published `.vsix` filename in every doc that quotes it (`vscode-extension/README.md`, `docs/vscode-extension.md`, project root `README.md` integrations table) so that anyone copy-pasting the install command lands on the artefact that's actually attached to the latest release. This synchronisation is now a hard rule — see the new "VS Code extension version sync" section in `CONTRIBUTING.md`: every `.vsix` filename quoted in user-facing docs must match `vscode-extension/package.json#version`, and any version bump in `package.json` is incomplete until those references are updated and the `vsce package` step re-runs.

---

## [0.1.19] — 2026-05-09

### Added
- 📦 **Self-contained `.vsix` — no repo clone required.** `scripts/bundle-engine.js` copies the engine **and catalog** from the source repo into the extension at build time (wired into `vscode:prepublish`, `prepackage`, and `pretest` so it runs before every relevant npm step). The bundled layout mirrors the source repo —`engine/scripts/detect.py` + `engine/catalog/*.yaml` — so detect.py's default `--catalog` resolution (`Path(__file__).parent.parent / "catalog"`) finds the catalog automatically, no extension-side flag plumbing required. `scriptResolver.resolveScriptPath()` checks the bundled location *first* — before the `tf-analyze.scriptPath` setting and any workspace fallbacks — so a fresh `code --install-extension tf-analyze-X.Y.Z.vsix` works out of the box on any workspace, with no settings to configure and no companion repo to clone. The extension is now ~1MB packaged: 313KB engine + 339KB catalog (209 rule YAMLs + the catalog README) + 359KB language-client deps.

  **Self-containment is a hard product requirement going forward.** Any new runtime that the extension needs (a future remediation engine, a SAT solver, etc.) MUST be bundled the same way — the user-facing install must never depend on a separate `git clone`, `pip install`, or `apt install` step. The workspace-fallback paths are now considered *engine-developer escape hatches only*, not user features.

### Removed
- **Report status-bar icon (`📄 Report`).** The HTML report panel and the Findings tree present the same data with different ergonomics, and toolbar real estate should be reserved for surfaces that give the user net-new information at a glance. The `tf-analyze: Show Report` command is still wired up — it appears in the Command Palette and in the Findings tree's view-title bar — just not in the status bar. Status bar now reads "scan · graph · delta · compliance · remediate" left-to-right (five items).

### Changed
- **Resolver tests use `bundledEnginePath: null` to disable the bundled-engine check** so they exercise the workspace-fallback chain without picking up the real bundled engine the build step just produced. Two new tests cover the bundled path itself: one verifies it points at `<extensionRoot>/engine/detect.py`, the other verifies it wins over a workspace-relative fallback when both exist.

---

## [0.1.18] — 2026-05-09

### Fixed
- **Every command in 0.1.14–0.1.17 was unreachable from a fresh install.** Symptom: `command 'tf-analyze.showAttackGraph' not found` (and the same for every other command, the status-bar items never appearing, etc.). Root cause: `.vscodeignore` excluded `node_modules/**`, but `vscode-languageclient` was added as a runtime dependency in 0.1.14. The packaged `.vsix` therefore shipped without the module on disk; at extension load time `require('vscode-languageclient/node')` (transitively, via `lspClient.ts`) raised `MODULE_NOT_FOUND`, the entire `extension.js` module failed to load, `activate()` never ran, and no commands or status-bar items ever got registered. The "Missing property icon" report (0.1.16) and the "speed bar icons not displaying" report (0.1.17) were both downstream symptoms of the same packaging bug — VS Code happened to surface different parts of the failure depending on which contribution it was inspecting at the time. Removed the `node_modules/**` ignore rule so `vsce` ships runtime deps as it's meant to. The published .vsix is now 734KB / 338 files instead of 280KB / 24 files — the extra weight is the `vscode-languageclient` tree (and its `vscode-jsonrpc` / `vscode-languageserver-protocol` / `vscode-languageserver-types` transitive deps), all of which is required at runtime.

---

## [0.1.17] — 2026-05-09

### Fixed
- **Status-bar items didn't appear in fresh VS Code windows even when the workspace contained `.tf` files.** `activationEvents` only listed `onLanguage:terraform` (fires when a `.tf` file becomes the active editor) and `onView:tfAnalyzeFindings` (fires when the Findings view is opened). If a user opened a Terraform workspace and didn't immediately open a `.tf` file or the Findings view, the extension stayed dormant — `activate()` never ran, no `createStatusBarItem` calls happened, and the toolbar stayed empty. Added `workspaceContains:**/*.tf` so the extension wakes up the moment VS Code finishes scanning a workspace that contains Terraform code, regardless of which file the user is looking at.

---

## [0.1.16] — 2026-05-09

### Fixed
- **Manifest validation error: "Missing property icon" on activation.** `tf-analyze.clearFindings` was wired into the `view/title` `navigation` group but its command declaration had no `icon` field — VS Code's contribution-point schema requires one for any command rendered as a navigation button. The error surfaced louder in 0.1.15 because the same view-title bar now hosts six other navigation commands; the previously-quiet warning becomes a hard validation failure once VS Code starts caching the contribution registry across reloads. Added `$(clear-all)` to the command declaration. The other icon-less commands (showMitre, suppressFinding, unsuppressFinding, openBaseline, openFinding, applyFix) are command-palette / context-menu only — never rendered as buttons — and don't need icons.

---

## [0.1.15] — 2026-05-09

### Added
- 🪄 **Remediation panel.** New `tf-analyze: Remediate` command + status-bar item (`$(wand) Remediate`, priority 95) opens a webview that runs `detect.py --apply-fixes dry-run` and renders the resulting unified diff with syntax highlighting (file headers gold, hunks grey, additions green, deletions red). Two-stage UX — the **Apply Fixes** button asks for explicit confirmation before re-running with `--apply-fixes apply`, which writes the patched files to disk and saves originals as `<file>.bak` alongside. Empty state explains which fix kinds (`resource_missing_arg`, `resource_arg`, `hcl_attr`) are eligible for bulk patching vs. which need the in-editor Quick Fix flow.
- 🧪 **Test suite.** New `npm test` runs 22 tests via `node --test` covering baseline (suppress/unsuppress idempotency, corrupted-file recovery, distinct-key handling), scriptResolver (file vs. directory, parent walk, configured-path fallbacks), and four end-to-end engine smoke tests that spawn `python3 detect.py` to confirm the fixes for `--apply-fixes IsADirectoryError` and `--format compliance` `_ctrl_sort_key` don't regress. Tests skip gracefully when `python3` isn't on PATH.

### Changed
- **`baseline.ts` and `scriptResolver.ts` are now pure node modules.** Removed runtime `vscode` import from `baseline.ts` (`openBaselineFile` moved to extension.ts where the vscode call lives) and converted `scriptResolver.ts`'s vscode import to `import type` only. Both modules can now be exercised by `node --test` without an Electron host.

### Fixed
- **Engine `--apply-fixes` crashed with `IsADirectoryError` on absent-resource findings.** `_handle_apply_fixes` in `scripts/detect.py:6228` was filtering candidate files with `path.exists()`, but absent-resource findings (kind=`resource_missing_arg` with no source file) carry the **target directory** in their `file` field, not a real path. `exists()` returned True for those entries and the code fell through to `open(<directory>)`. Switched to `path.is_file()` which filters out directories too. End-to-end smoke test (`engineSmoke.test.ts`) covers this regression.

---

## [0.1.14] — 2026-05-09

### Added
- ⚡ **Real-time LSP diagnostics.** New language client connects to `python3 detect.py --lsp` over JSON-RPC stdio, so diagnostics + Quick Fix update as you type instead of only on save. Falls back to the legacy exec-on-save path silently if the LSP server can't start. The exec-based whole-workspace scan is unchanged — it still powers the Findings tree view and runs from the status-bar shield. Adds `vscode-languageclient@^9` as a runtime dependency.
- 🔀 **Delta panel.** New `tf-analyze: Since Last Scan` command + status-bar item (`$(diff) Delta`, priority 97) opens a webview running `--auto-compare` against the most recent prior JSON report. Surfaces three groups: **New** (in red, click to open the file), **Resolved** (in green, motivational), and **Unchanged** (counter only). Empty-state copy explains how to seed a baseline scan.
- ✅ **Compliance panel.** New `tf-analyze: Show Compliance Report` command + status-bar item (`$(checklist) Compliance`, priority 96). Toolbar dropdown switches live between **CIS**, **PCI DSS**, **SOC 2**, and **All** without leaving the panel. Same iframe-srcdoc rendering as the regular HTML report, with **Open in browser** for full-fidelity print/export.
- 🎯 **MITRE ATT&CK view.** New `tf-analyze: Show MITRE ATT&CK View` command opens a webview that runs `--format mitre`, parsing the engine's markdown-style technique grouping into styled headings + urgency-tagged finding rows. Command palette only — the status bar already has five entries.
- 🚫 **Baseline / suppression UI.** Right-click a finding in the Findings tree → **Suppress finding (add to baseline)**. Writes to `<workspace>/.tf-analyze-baseline.json` (the same shape the engine accepts via `--baseline`). The runScan exec path now auto-detects this file at the workspace root and passes `--baseline` so subsequent scans suppress matching `(id, file, line, resource)` records. **Unsuppress finding** reverses it. **Open Baseline File** opens the JSON in the editor for bulk editing.

### Changed
- **Engine `--format compliance` bug fixed upstream.** `_ctrl_sort_key` in `scripts/detect.py` was returning a list of mixed `int` / `str` parts; Python's tuple-comparison choked when control IDs like `"AC-2.a"` and `"1.2.3"` met during sort. Wrapped each part in `(0, int)` or `(1, str)` so comparisons are always tuple-vs-tuple between like types. The compliance panel was the trigger to fix this — without it, `--format compliance` and `--format html --compliance` both crashed with `TypeError: '<' not supported between instances of 'str' and 'int'`.
- **runOnSave coexists with LSP.** When the LSP server is up, the legacy exec-on-save handler is skipped to avoid double-writing diagnostics. Tree refreshes still happen on the manual `tf-analyze: Run Scan` command.
- **Auto-suppress when baseline file exists.** `runScan` adds `--baseline <path>` whenever `<workspace>/.tf-analyze-baseline.json` is present. Findings in the baseline disappear from the tree until removed via the unsuppress command or by editing the file directly.

---

## [0.1.13] — 2026-05-09

### Added
- 📄 **HTML report panel.** New `tf-analyze: Show Report` command opens the engine's `--format html` output inline in a webview, with a toolbar offering **Refresh** and **Open in browser** (writes to a temp file and hands off to the OS handler for full-fidelity printing/sharing). The engine's HTML is fully self-contained — inline CSS, no external scripts, no CDN — so it drops into a webview iframe (`srcdoc`) with no CSP rewriting needed.
- 🛠 **Status-bar shortcut for the report.** A third item joins the existing `🛡 tf-analyze` (scan) and `🛤 Attack Graph` shortcuts: `$(file-text) Report` at priority 98, immediately right of the attack graph. The three read left-to-right as "scan · graph · report" and are gated on the workspace containing at least one `.tf` file.
- **View-title menu entry.** The Findings tree-view title bar now also exposes the report shortcut alongside the attack-graph icon.
- **Per-section / extra-args plumbed through.** The HTML report respects the existing `tf-analyze.section` and `tf-analyze.extraArgs` settings, so the rendered report matches whatever filter the rest of the extension is using.

### Changed
- **Script-path resolution unified.** Both panels (attack graph and HTML report) now share a single `scriptResolver.resolveScriptPath()` helper, so a fix in one surface benefits the other automatically. This was a noted goal from the 0.1.8 release notes — finally factored out now that there are two consumers.

---

## [0.1.12] — 2026-05-09

### Fixed
- **Attack graph webview crashed inside `d3.v7.min.js` with `Uncaught Error: node not found: undefined` for every workspace that actually had edges.** The engine emits edges as `{ from, to, label }`, but `d3.forceLink` reads `{ source, target }` and resolves the endpoints via `.id(d => d.id)`. Without aliasing, d3 saw `source = undefined` on every link, looked up node id `undefined`, and threw before any nodes rendered. The webview now maps `from → source` and `to → target` when populating the edge array, leaving the engine's wire format untouched. This rendering path had never run end-to-end before — 0.1.8/0.1.9 fixed *empty-panel* edge cases, and 0.1.10/0.1.11 fixed *script-resolution* failures, both of which short-circuited before d3 was reached.

---

## [0.1.11] — 2026-05-09

### Fixed
- **Attack graph failed with `can't find '__main__' module in '…/scripts'` when the configured `tf-analyze.scriptPath` pointed at the scripts *directory* rather than the `detect.py` file inside it, or when the workspace was opened on a subfolder of the tf-analyze repo (e.g. a fixture).** `_resolveScriptPath` was accepting any path that existed — including directories — so `python3 <dir>` ran with no `__main__.py` and crashed before emitting JSON. The resolver now requires a regular file, treats a configured directory as "look for `detect.py` inside", and walks up to six parent directories of the workspace looking for `scripts/detect.py`. The 0.1.10 diagnostic surfaced this as `detect.py exited without printing JSON` with the bad command line — that's the path that revealed the root cause.

---

## [0.1.10] — 2026-05-09

### Fixed
- **Attack graph showed `Unexpected end of JSON input` with an empty stdout dump and no clue what went wrong.** `detect.py` exits 1 both when findings exist (expected) *and* when Python raises an unhandled exception — in the second case stdout is empty and the traceback is on stderr. The webview was treating any exit code ≤ 1 as success and falling through to `JSON.parse('')`, hiding the only useful diagnostic. The error path now triggers on empty/whitespace stdout regardless of exit code, surfaces the captured stderr, and shows the exact reproduction command so the underlying Python error is visible directly in the panel.

---

## [0.1.9] — 2026-05-09

### Fixed
- **Attack graph rendered an empty panel for workspaces with no resources at the root.** The 0.1.8 fix correctly read the JSON under `data.graph` and tightened the empty check to `nodes.length === 0`, but `build_attack_graph` always emits a synthetic `INTERNET` entry node, so for a workspace with no `.tf` resources the webview saw `nodes.length === 1` and rendered a single floating red dot. The empty-graph guard now ignores the synthetic entry node and also requires at least one edge — if neither holds, the panel surfaces the dedicated help text.

### Changed
- **Empty-graph help panel now shows the actual `--target` path that was scanned**, plus three concrete causes (workspace-root mismatch · no internet entry point · only modules/providers/data sources) and the exact terminal command you can paste to reproduce. Most users hitting this had opened a parent folder or the extension subfolder as the workspace root rather than the directory containing their `.tf` files.

---

## [0.1.8] — 2026-05-09

### Fixed
- **Attack graph webview rendered an empty panel.** The webview was reading the JSON output under `data.attack_graph`, but `detect.py` has emitted the graph under `data.graph` since v0.2 (Round 25). The reader now accepts both keys for backwards-compat with users running pinned older `detect.py` builds, but prefers the canonical `graph` key.
- **Critical-path edges weren't highlighted in red.** The webview was checking `edge.label === 'critical'`, but edge labels are actual relationship names (`security_group`, `iam`, etc.). Critical-path information lives at `graph.critical_path` as a node-ID list; the webview now derives `is_critical` per edge by walking consecutive pairs.
- **Silent failure modes.** When `detect.py` errored, was missing, or produced unparseable output, the catch block swallowed everything and rendered a blank SVG. The webview now surfaces a dedicated error panel for each failure class (script not found, scan exit code > 1, JSON parse error, empty graph) with the underlying stderr or stack trace and a hint at how to fix it.
- **Fragile script-path lookup.** The graph view used a different (weaker) resolution path than the main scan, so workspaces with the tf-analyze repo cloned alongside (e.g. `~/projects/my-tf` next to `~/projects/tf-analyze`) couldn't find `detect.py`. The two surfaces now use the same lookup order: `scriptPath` setting → `scripts/detect.py` in workspace → `detect.py` in workspace → `../tf-analyze/scripts/detect.py`.

---

## [0.1.7] — 2026-05-09

### Added
- 🛤️ One-click **Attack Graph** shortcut in the status bar. Sits next to the existing scan shield (priority 99 — immediately to the right of `$(shield) tf-analyze`) and opens the internet → crown-jewels webview on click. The shortcut only appears when the workspace contains at least one `.tf` file, so non-Terraform projects don't see a useless button.

### Background
The attack-graph view was previously only reachable from the Command Palette, the Findings view's title bar, or the walkthrough. The status-bar shortcut takes it from a 3-keystroke flow to a single click — important because the graph is the extension's most distinctive feature and the one users tend to screenshot.

---

## [0.1.6] — 2026-05-08

### Fixed
- Status-bar counters showing `C:undefined H:undefined M:undefined`. The extension was reading legacy lowercase keys (`summary.critical/.high/.medium`) but `detect.py` emits the counts under `summary.counts` with uppercase severity keys. The `ScanResult` type and status-bar render were updated to match the engine's actual output contract.

---

## [0.1.5] — 2026-05-08

### Added
- 🖼️ Hero illustration in the README and a dedicated **Getting Started** walkthrough that VS Code now surfaces on first install (3 steps: connect the engine → run your first scan → explore findings).
- 📋 This `CHANGELOG.md`, rendered as a dedicated tab on the Marketplace listing.

### Changed
- README polish: requirements, troubleshooting, and a worked `settings.json` example.

---

## [0.1.4] — 2026-05-08

### Added
- Initial public README with feature overview, quickstart, settings reference, and troubleshooting.

### Fixed
- Status-bar example in docs corrected to the real format produced by the extension (`🛡 tf-analyze: N (C:x H:x M:x)`).

---

## [0.1.3] — 2026-05-08

### Added
- 🛡️ **Dedicated Activity Bar icon** — `tf-analyze` now claims its own slot on the left rail with a monochrome shield-and-magnifier silhouette that re-tints to the active theme.
- New `viewsContainers.activitybar` contribution moves the **Findings** tree out of the Explorer into its own container.
- `onView:tfAnalyzeFindings` activation event so the extension wakes up when the panel is opened, even with no `.tf` file in the editor.

### Changed
- Findings view title trimmed from "tf-analyze Findings" to "Findings" since the container itself is titled "tf-analyze".

---

## [0.1.2] — 2026-05-08

### Fixed
- Re-rendered the marketplace icon through `librsvg` after discovering ImageMagick had silently dropped the shield path, magnifier handle, code lines, and check badge during the previous render.

---

## [0.1.1] — 2026-05-08

### Changed
- Marketplace icon up-rendered from 128 × 128 to 1024 × 1024 for crisp display on retina screens. (Note: this build shipped a partial render — superseded by 0.1.2.)

---

## [0.1.0] — 2026-05-08

### Added
- 🔴 **Inline diagnostics** for Terraform files via the `tf-analyze` detection engine (192 catalogue rules across AWS, GCP, and Azure).
- ⚡ **Quick Fix** code-action provider for rules with `fix_hcl` support.
- 🌳 **Findings** tree view, grouped by file and severity.
- 🕸️ **Attack-graph** webview visualising IAM, networking, and KMS reachability between resources.
- 💾 **Run-on-save** with a configurable toggle.
- Configurable scan section (`security` / `robustness` / `ops` / `module` / `stack` / `style`), urgency threshold, and CLI passthrough flags.
- Status-bar item showing the live finding count.
