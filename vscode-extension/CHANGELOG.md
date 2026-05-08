# Changelog

All notable changes to the **tf-analyze** VS Code extension are recorded here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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
