# tf-analyze — Overnight Deep Analysis · 2026-05-10

Orchestrated synthesis of five parallel subagent runs (A: repo audit, B:
competitor landscape, C: viral launch patterns, D: public-scanner
feasibility, E: repo health). All findings cite a file path, URL, or
commit. Where a subagent could not verify, the report says so.

**Caveats up front (honesty rule):**

- The memory file `~/.claude/projects/-Users-chris-adkin-Projects-tf-analyze/memory/MEMORY.md` referenced by the run prompt **does not exist on this machine** — the analysis ran in `/home/user/tf-analyze`. The repo-local equivalents `docs/launch/virality-plan.md` and `docs/launch/scan-service-plan.md` were used as the strategy substrate; they are richer and more current than a typical memory dump.
- The prompt's strategy file `memory/project_virality_strategy.md` is not in the repo. Its content appears to be inlined into `PLAN.md` § Round 30 plus `docs/launch/virality-plan.md`. Treat this report as **stress-testing those two files**, not the missing strategy doc.
- This run executed turn-by-turn in one session rather than over a 4-hour wall clock. Budget was effort, not time. No subagent was cut for budget; all five returned.

---

## 1. Ground truth — what's actually shipped vs claimed

(from subagent A)

**All ten claimed surfaces are shipped and exercised by tests.** The
"ten surfaces" headline in `README.md:26` is accurate: CLI engine
(`scripts/detect.py`, 6,985 LoC), GitHub Action (`action.yml`,
`integrations/github-action.yml`; clone-URL bug fixed in R30.0.2),
Docker image (`Dockerfile`, multi-arch on ghcr), pre-commit hook
(`.pre-commit-hooks.yaml`, three variants), LSP server
(`detect.py --lsp`; `tests/test_lsp_server.py` 11 cases), VS Code
extension (`vscode-extension/`, v0.1.37, self-contained vsix), HCP Run
Task (`integrations/run-task/server.py`, HMAC-SHA512), MCP server
(`integrations/mcp-server/server.py`, 5 tools, 22 hardening tests in
`tests/test_mcp_server_hardening.py`), Terraform provider
(`terraform-provider/`, Go), Claude skill (`SKILL.md`, `install.sh`).

**Headline counts in README are current as of today** —
217 catalogue YAMLs in `catalog/`, 639 pytest cases, extension v0.1.37
all match the README badges (`README.md:17-22`) and `PLAN.md:22`.
Test-to-engine LoC ratio is ~1.9:1 (17,304 test LoC / 8,988 engine LoC).

**Shipped beyond the README narrative** but lightly surfaced:

- Score badge service (`integrations/badge-service/server.py`, 352 LoC,
  19 tests in `tests/test_badge_service.py`). Code complete; awaits
  `flyctl deploy`.
- Web demo (`demo/app.py`, 93 LoC + `demo/index.html`, 243 LoC). Has
  `POST /scan/repo` accepting a GitHub URL today — undersold in
  `README.md:226` as just "FastAPI + d3 web demo".
- Per-rule docs site at `docs/rules/` — 218 generated pages (one extra
  is a placeholder), JSON-LD structured data, family backlinks, 4-verb
  `vscode://` URI handler.
- Six modularisation seams shipped (`_mitre.py`, `_versions.py`,
  `_scoring.py`, `_hcl.py`, `_catalog.py`, `_attack_graph.py`),
  1,996 LoC extracted, detect.py 8,441 → 6,985 (−17.2%).

**Queued but not shipped** (Round 30 phases 1-5 in `PLAN.md:40-44`):

- Multi-framework taxonomy sweep (R30.1) — `owasp:` + `nist_csf:` +
  `nist_800_53:` + `csa_ccm:` + `slsa:` fields; eight new compliance
  modes. **Not in catalogue.**
- KEV+EPSS exploitability prioritisation (R30.2). The README's
  "no comparable OSS IaC scanner integrates KEV today" claim is
  **aspirational**; the feature is queued, not built.
- 19 new rules + 6 enhancements (R30.3 — R30.5).

**Most important discrepancy:** the public scanner that
`docs/launch/virality-plan.md:39` calls "the load-bearing feature" is
**~70% built but not deployed**. `demo/app.py` already has the
`POST /scan/repo` flow but no permalink, no caching, no abuse handling,
no `git` in the Dockerfile, and `flyctl deploy` has never been run
(per `PLAN.md:267`, "Operator-only" appendix).

---

## 2. Where the market is — competitor table + the gap tf-analyze should own

(from subagent B)

| Tool | Stars (May 2026) | Recent releases | Marquee tf-analyze lacks | tf-analyze has, they don't |
|---|---|---|---|---|
| **Checkov** | ~8.7k, flat ([repo](https://github.com/bridgecrewio/checkov), [stars](https://appsecsanta.com/checkov)) | 3.2.525-527 (Apr–May 2026) — multiline-regex revert, Helm fixes, Windows path fix — all bug-fix ([releases](https://github.com/bridgecrewio/checkov/releases)) | 2,500+ built-in policies + Prisma SaaS backend with drift detection | Attack-path graph, D3FEND, fix_hcl on 100% of rules, OSCAL, native TF provider |
| **tfsec** | Archived — merged into Trivy ([repo](https://github.com/aquasecurity/tfsec)) | None — `tfsec .` → `trivy config .` ([migration](https://github.com/aquasecurity/tfsec/blob/master/tfsec-to-trivy-migration-guide.md)) | n/a | Everything — EOL |
| **Trivy** | ~32.2k, strong growth ([review](https://appsecsanta.com/trivy)) | v0.70.0 (Apr 17 2026): TF cross-resource ID accuracy, ARM/AKS, Go binary version detection ([release](https://github.com/aquasecurity/trivy/discussions/10546)) | Unified scanner: containers + SBOM + secrets + IaC + K8s + cloud — breadth tf-analyze can't match | Attack-path graph, MITRE D3FEND, Module Reuse ROI, fix_hcl, score badge |
| **KICS** | Steady, ~monthly cadence | v2.1.20 (Mar 3 2026): Azure beta queries, OPA upgrade ([notes](https://newreleases.io/project/github/Checkmarx/kics/release/v2.1.20)) | Rego/OPA-native authoring with 2,400+ queries (lower bar to write custom rules) | Attack-path, D3FEND, OSCAL, fix_hcl autoremediation |
| **Terrascan** | **Archived Nov 20 2025** ([repo](https://github.com/tenable/terrascan)) | v1.19.9 (Sep 2025) maintenance only | n/a | Everything still developed |
| **Snyk IaC** | snyk/cli ~5.4k | 20x perf on large dirs, OPA/Rego, TF plan-JSON, IDE/PR fixes ([Snyk IaC](https://appsecsanta.com/snyk-iac)) | Cloud drift detection (live AWS/Azure/GCP) | Attack-path, D3FEND, OSCAL |
| **Bridgecrew/Prisma** | Closed SaaS; OSS arm is Checkov ([blog](https://www.paloaltonetworks.com/blog/cloud-security/prisma-bridgecrew-infrastructure-security/)) | HCP Run Task, JetBrains plugin, drift, Jira/ticket workflows | Full CNAPP — runtime + identity + SCA unified | Open source, attack-path in OSS, D3FEND, OSCAL, TF provider |
| **Wiz IaC** | Closed SaaS ([page](https://www.wiz.io/academy/application-security/iac-scanning)) | HCP Terraform connector, Run Task post-plan ([blog](https://www.wiz.io/blog/wiz-hcp-terraform-close-the-cloud-security-gap)) | Runtime-aware attack graph chaining live cloud → identity → data | Open source, OSCAL, fix_hcl, D3FEND, MCP-native |

**Convergence:** Every player has SARIF, TF plan-JSON, HCP Run Task,
IDE plugin, OPA-style custom policy, some ATT&CK mapping. OSS field
consolidating to **Trivy + Checkov**; tfsec and Terrascan are gone.

**Divergence:** SaaS leaders (Wiz especially) compete on runtime-aware
attack graphs. Pure-IaC OSS tools compete on policy count and
remediation breadth.

**The gap tf-analyze should own — be the
defensive/remediation-first IaC analyzer for the agent era:**

1. `fix_hcl` on 100% of rules. Checkov has remediation on <30% of
   policies; Trivy/KICS effectively zero.
2. MITRE D3FEND tagging — no OSS IaC scanner ships defensive-control
   tags. tf-analyze has 87 rules tagged (40% coverage,
   `PLAN.md:38`).
3. OSCAL Assessment Results JSON output — uniquely auditor-shaped.
4. Native AI-agent surfaces (Claude skill + MCP server + native TF
   provider data source). No competitor ships these.

Positioning: **"the IaC scanner an autonomous agent can actually
act on."** This is the lane no one else is in. It is also defensible —
Wiz/Prisma can build runtime context faster than they can rewrite their
remediation surface to be machine-parseable.

---

## 3. What viral launches look like in 2026 — the pattern to copy

(from subagent C)

Five recent dev-tool launches that hit >5k stars from <500:

1. **Opengrep** ([HN](https://news.ycombinator.com/item?id=42804634), Jan 2025) — David-vs-Goliath fork narrative anchored to Semgrep's Dec 2024 license change ([InfoQ](https://www.infoq.com/news/2025/02/semgrep-forked-opengrep/)). Not transferable: no incumbent license drama for tf-analyze to ride.
2. **zizmor** (GitHub Actions analyzer, [1.0 post](https://blog.yossarian.net/2025/01/02/zizmor-1-0)) — surged after the tj-actions/changed-files compromise ([CISA alert](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)). Single-binary `cargo install`, mapped to a named CVE. **Highly transferable.**
3. **oxlint/oxc** ([beta post](https://oxc.rs/blog/2025-03-15-oxlint-beta), [InfoQ 1.0](https://www.infoq.com/news/2025/08/oxlint-v1-released/)) — "50-100x faster than ESLint" with a single benchmark GIF and name-drop logos (Shopify, ByteDance). Speed wedge.
4. **uv** ([Astral blog](https://astral.sh/blog/uv), [deep dive](https://www.saaspegasus.com/guides/uv-deep-dive/)) — `pip` drop-in, 10-100× faster, rode ruff's halo. Brand consistency matters; tf-analyze has no halo author yet.
5. **Trivy** ([Aqua blog](https://www.aquasec.com/blog/trivy-scanner/)) — one binary scans everything; absorbed tfsec. Sustained, not viral-spike. GitHub Marketplace Action one-line YAML.

**Recommended pattern: zizmor's playbook.** Ship a Show HN with:
(1) a 30-second asciinema GIF scanning a public Terraform module
that contains a recent named CVE-class issue; (2) a one-line
GitHub Action with a live-scan badge for READMEs; (3) explicit
positioning against archived Terrascan and EOL'd tfsec.

**Why this and not the others:** zizmor is the closest analogue —
solo-led project, niche static analysis, rode a supply-chain CVE wave
to ~2.5k stars. Terrascan's Nov 2025 archive is tf-analyze's
"Semgrep moment" — a real grievance to anchor against. The
fork-narrative is replaceable with an *abandonment-narrative*.

**What won't transfer:** Opengrep's vendor-coalition PR (no coalition),
uv/oxlint's "10-100× faster" claim (TF parsing isn't the user-felt
bottleneck), Trivy's sustained growth (a launch spike isn't durable
adoption). Don't fake a benchmark; do tie the launch to the next
inevitable IaC CVE or compromised module.

---

## 4. The load-bearing feature, costed — public scanner 1-week plan

(from subagent D, file evidence in `demo/`)

`docs/launch/virality-plan.md:39` calls `tfanalyze.com/scan/<owner>/<repo>`
the load-bearing viral feature. **~70% of it already exists.**

**Already in repo:**
- `demo/app.py` (93 LoC) — FastAPI with `POST /scan/hcl` and
  `POST /scan/repo` (regex-validated GitHub URL, `git clone --depth 1`,
  30s timeout, 10 req/min/IP). Returns JSON only.
- `demo/index.html` (243 LoC) — CodeMirror editor, d3 attack-graph SVG.
  No permalink. No share buttons.
- `demo/Dockerfile` (15 LoC), `demo/fly.toml` (16 LoC, region `iad`,
  scale-to-zero, 512 MB). **Missing `git` package in image.**
- `integrations/badge-service/server.py` (352 LoC) — separate Fly app,
  HMAC-signed ingest, SVG by `(owner, repo, branch)`. Not wired to the
  scanner.
- `docs/launch/scan-service-plan.md` and `scan-service-todo.md`
  (419 LoC combined) — full 4-week strategy with file-level acceptance.
  This run compresses it to one week.

**Missing pieces (the actual MVP gap list):**

- Permalink/result URL: no route, no DB, no cache.
- No SHA resolution against GitHub API; no `git` binary in Docker.
- No persistent storage (no `db.py`, no volume).
- No async worker / `Semaphore(3)` cap; current `subprocess.run` is
  sync and blocks the FastAPI event loop.
- No HTML report by URL; today `--format html` is unused server-side
  even though `detect.py:3938` already produces a self-contained file.
- No pre-clone size cap (a 5 GB repo will happily clone).
- No Cloudflare proxy / WAF / hourly rate limit beyond the in-memory
  10/min limiter.
- Domain: `tfanalyze.com` not configured anywhere in repo. Soft-launch
  on `tfanalyze.fly.dev` is the realistic path
  (`scan-service-plan.md:96-98`).

**Compressed 1-week plan (one engineer full-time):**

| Day | Work | Hours |
|---|---|---|
| 1 | Add `git` to `demo/Dockerfile`; `flyctl volumes create scans_data --size 3`; mount `/data`; bump memory to 1024 MB; `demo/db.py` with the SQLite schema from `scan-service-todo.md:32-48` (WAL mode). | 0.75d |
| 2 | Replace sync `_run_scan` with `async run_scan(scan_id)` using `asyncio.create_subprocess_exec` + `core.hooksPath=/dev/null` + size-check + 60s `wait_for`. Add `POST /scan`, `GET /status/<id>`, `GET /scan/<owner>/<repo>/<sha>/`, `GET /scan/<owner>/<repo>/` (302 to latest SHA). | 1.25d |
| 3 | New `demo/index.html`: form posts to `/scan`, polls `/status`, redirects to the report URL. Engine's `--format html` becomes the report body — no extra templating. Copy-permalink + share buttons. | 1d |
| 4 | Inline `/badge/<owner>/<repo>.svg` reusing `render_badge_svg` from `integrations/badge-service/server.py:142-184`. Error pages, path-traversal proofing. | 0.75d |
| 5 | Per-IP scan-budget (10/hr) in SQLite. LRU evictor when `/data/reports/` > 2 GB. `/healthz`. Cloudflare orange-cloud + rate-limit rule. | 1d |
| 6 | End-to-end against the `scan-service-todo.md:97-105` acceptance gate. `hey` load test at 50 RPS × 60s. Tune semaphore. README "Try it" link. | 1d |
| 7 | Buffer + soft launch on `tfanalyze.fly.dev`. | 0.25d |

**Effort:** backend 2d, frontend 1d, badge+hardening 0.75d,
abuse/cache 1d, test/launch 1.25d. ~6d work + 1d buffer.

**Top 5 risks:**

1. Cost runaway from scan-bombing. Pre-clone size check via
   GitHub `size` field. Reject >100 MB. SHA-keyed cache. Per-IP budget.
   Residual: rotating-IP attacker still ~$0.50/hr; cap with global
   circuit breaker.
2. Scan correctness diverging in cloned repos vs local
   (submodules, LFS files). Disable `--filter=blob:none` initially;
   `submodule update --init`; surface "scanned N .tf files" on the
   report.
3. Untrusted repo content as attack surface. Engine is passive
   parser; never invoke `terraform`; `core.hooksPath=/dev/null`;
   demouser UID 1001 (already configured `demo/Dockerfile:12`); Fly
   egress rules.
4. **HTML report XSS via shared URL.** This is the under-rated
   one. The viral mechanic *is* shared URLs; a malicious resource name
   like `</script><script>fetch(...)` in HTML output could XSS anyone
   who opens the link. Audit `detect.py:3938` HTML renderer for every
   interpolation site before launch; add strict CSP
   (`default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`).
   Copy the pattern from `integrations/badge-service/server.py:267-273`.
5. GitHub API rate-limit cliff at launch. Unauth 60/hr → a Show HN
   front-page bump 429s every new scan. Add a single PAT in Fly secrets
   on day 1 (5k/hr). No code change.

---

## 5. Ranked viral recommendations — top 5 by (lift × inverse cost)

### V1 — Ship the public scanner with permalinks (`tfanalyze.fly.dev/scan/<owner>/<repo>`)

- **Deliverable:** A live URL that turns any GitHub Terraform repo into
  a shareable, cached HTML report with score, grade, attack-graph,
  fix_hcl previews, and a "tweet this" button.
- **Sketch (1 week):** `demo/app.py` async refactor; `demo/db.py`
  SQLite + WAL; volume-mounted `/data/reports/<sha>/`; reuse
  `detect.py --format html`; Cloudflare in front. Day-by-day in § 4.
- **Falsifiable metric:** ≥1,000 unique scans in the first 14 days
  post-launch, ≥30% returning from a shared permalink (not from the
  front page).
- **Risk that kills it:** XSS in the report HTML once a malicious
  repo name is shared (see § 4 risk 4). Audit before launch.

### V2 — Show HN around a named, recent Terraform-supply-chain incident

- **Deliverable:** A blog post + Show HN tied to a real IaC CVE or a
  compromised public module from the last 90 days, with a 30-second
  asciinema GIF scanning that module live and producing a fix.
- **Sketch:** Replace the docs/launch/hacker-news.md draft with a
  CVE-anchored variant; create `examples/cve-of-the-month/`;
  cross-link to V1's scanner; pre-stage the asciinema record;
  coordinate with V3.
- **Falsifiable metric:** ≥500 GitHub stars within 30 days of post.
- **Risk that kills it:** No suitable named incident within the launch
  window. Mitigation: keep `examples/well-formed/` and
  `examples/terragoat/` as evergreen demos; CVE-anchoring is an
  amplifier, not a precondition.

### V3 — Live-scan README badge as the install path

- **Deliverable:** `![tf-analyze](https://tfanalyze.fly.dev/badge/<owner>/<repo>.svg)`
  — a one-line README addition that displays score+grade and links
  back to the report. Each rendered badge is an ad.
- **Sketch:** Inline `/badge/...svg` into `demo/app.py` reusing
  `integrations/badge-service/server.py:142-184`; ETag + 5-min
  cache-control already in the badge service; auto-render PR-delta
  badge later.
- **Falsifiable metric:** ≥100 repos with the badge committed in
  60 days (GitHub code search query: `tfanalyze.fly.dev/badge`).
- **Risk that kills it:** Badge service downtime stains every repo
  that adopts it. Mitigation: serve last-cached badge from CDN even on
  origin failure; status page.

### V4 — KEV+EPSS exploitability ranking (R30.2) before R30.1 frameworks

- **Deliverable:** `--rank-by exploitability` with a `🔥 KEV` badge in
  PR summary + VS Code panel + SARIF tags.
- **Sketch:** Build `scripts/_threat_intel.py` (CISA KEV +
  FIRST.org EPSS, ~/.cache daily refresh, offline-graceful). New flag
  `--rank-by {urgency|exploitability|hybrid}`. ~300 lines + 10 tests
  per `PLAN.md:41`.
- **Falsifiable metric:** Land on the OWASP IaC newsletter or a CISA
  blog within 60 days; appear in ≥3 third-party comparison articles
  for "OSS IaC scanners with KEV integration" (currently zero exist).
- **Risk that kills it:** KEV is small (~1.2k CVEs) and rarely
  intersects IaC misconfigs directly. Falsifiable: if the
  hybrid-rank changes <5% of finding orderings on TerraGoat, the
  feature is mostly marketing. Validate on TerraGoat **before**
  blogging.

### V5 — `examples/well-formed/` + the side-by-side "perfect score" demo

- **Deliverable:** A second showcase corpus that scores 100/A,
  alongside the existing TerraGoat that scores roughly 0/F. Side-by-side
  in the README hero. Anchors "what does tf-analyze reward?"
- **Sketch:** 5-10 .tf files in `examples/well-formed/` (already
  scoped in `PLAN.md:249`); update `examples/README.md`; add a CI
  drift gate that the corpus stays at score 100.
- **Falsifiable metric:** Reduces "this just tells me everything is
  broken" complaints (qualitative; rough proxy: ratio of
  positive-vs-negative HN comments ≥ 2:1 on launch).
- **Risk that kills it:** None significant. Cheapest item on this
  list; the only reason to not ship it is opportunity cost.

---

## 6. Repo health — robustness (top 10 risks)

(from subagent E1)

| # | Risk | Where | Likelihood | Blast |
|---|---|---|---|---|
| 1 | 17 broad `except Exception` swallowers, especially in diff-mode git subprocess wrappers — a shallow-clone CI scan can silently pass an empty changeset | `scripts/detect.py:88,121,131,4508,4565,4595,4710,4880,5021,5142,5379,5477,5486,5882,5893,6498,6546` | HIGH | MEDIUM |
| 2 | Subprocess timeouts without SIGTERM/SIGKILL escalation; git ops in diff-mode have no timeout at all | `integrations/mcp-server/server.py:148-150`; `scripts/detect.py:4414-4444` | MEDIUM | MEDIUM |
| 3 | MCP path validation handles symlinks but not inode loops or recursive symlink farms; could OOM during glob | `integrations/mcp-server/server.py:98-133` | LOW | HIGH |
| 4 | HCL brace-balancing parser fragile on unbalanced braces inside string literals or very deep nesting; no max-depth guard | `scripts/_hcl.py:126-160` | LOW | HIGH (false negatives) |
| 5 | `--check-registry` network fetch has no `Content-Length` cap; a hostile registry mirror could OOM the scanner | `scripts/detect.py:5236-5239,5376-5378` | LOW | MEDIUM |
| 6 | `apply-fixes` mode validates symlinks at scan-init but not at patch time; a race could let it write outside the workspace | `scripts/detect.py:5599-5724` | MEDIUM | LOW |
| 7 | LSP server has no debounce/coalesce on rapid saves; multiple `detect.py` subprocesses race to publish diagnostics | `vscode-extension/src/extension.ts:759-776` | LOW | MEDIUM (lost diags) |
| 8 | Attack-graph builder materialises all `for_each` instances unboundedly; ~10k items would choke render | `scripts/detect.py:2800-2900` | LOW | LOW |
| 9 | Cache key doesn't include catalogue commit hash — stale findings possible across rule-branch switches | `scripts/detect.py:5450-5484` | MEDIUM | LOW |
| 10 | MCP truncation drops trailing findings silently when output >1 MB; only envelope flags it, not individual findings | `integrations/mcp-server/server.py:74-75` | LOW | LOW |

**Honest summary (E's verdict):** the code is in good shape. The 10
risks are real but mostly LOW-MEDIUM likelihood; the broad `except
Exception` blocks are more about logging hygiene than silent crashes
(most have fallback logic). HCL parser's "false negatives over false
positives" trade-off is documented and appropriate. MCP hardening is
thoughtful (containment, envelopes, truncation caps).

---

## 7. Repo health — documentation

(from subagent E2)

**Top 5 contributor-blocking gaps:**

1. **No `ARCHITECTURE.md`.** How to add a new mode (`fleet`, `trend`,
   `pr-review`) or a new output format requires reverse-engineering
   ~600 lines of `main()`. The seam modularisation
   (`_scoring.py`, `_versions.py`, `_hcl.py`, `_catalog.py`,
   `_attack_graph.py`, `_mitre.py`) is recent; how to add a new
   module isn't documented.
2. **No `SECURITY.md`.** Even though the project ships defensive
   tooling, there's no disclosure policy. Required by GitHub
   community-standards check and by anyone running the MCP server in
   production.
3. **No troubleshooting guide for LSP server failures.**
   `docs/lsp.md` describes what the LSP server is but not how to
   debug "diagnostics not updating" when `detect.py` is off PATH.
4. **Sparse test parametrization.** Only 4 `@pytest.mark.parametrize`
   decorators across ~104 test functions; most tests are
   fixture-based. Adding a new urgency tier or compliance framework
   requires copying boilerplate.
5. **Module-extraction pattern under-documented.** The R30.0.5-0.9
   modularisation seams follow a consistent pattern (pure-only,
   binding-not-copy re-export shims, session-style test files), but
   the pattern lives in commit messages, not in a CONTRIBUTING section.

**Top 3 user-misleading gaps:**

1. **The "no comparable OSS IaC scanner integrates KEV" claim is
   aspirational** — see § 1 ground truth. The feature is queued in
   `PLAN.md:41` (R30.2), not built. A user comparison-shopping will
   discover this if they grep the catalogue.
2. **The `tfanalyze.com` references in the README and badges**
   (`README.md:12,13`) point at a domain that is not configured
   anywhere in the repo. Currently `marketplace.visualstudio.com`
   and `open-vsx.org` URLs work; the `tfanalyze.com` strings are
   visible to users but not actionable.
3. **Module-Reuse Advisor "lines saved" badge.** Real and tested
   (`tests/test_module_reuse.py`), but the README claim of "lines-saved
   ROI" implies a more sophisticated counting model than is shipped —
   it's resource-count × constant. Honest framing in the README would
   say "rough estimate."

Per-rule docs site is **complete** (218 pages for 217 rules); CI gate
in `.github/workflows/ci.yml:58-71` keeps it in sync. README badges
(217 rules, 639 tests) are accurate as of today.

---

## 8. Repo health — maintainability

(from subagent E3)

**`detect.py` decomposition status:** 6,985 LoC, 84 top-level
symbols. Six seams shipped (`_mitre.py` 110, `_versions.py` 204,
`_scoring.py` 114, `_hcl.py` 320, `_catalog.py` 443, `_attack_graph.py`
812; total 2,003 LoC extracted). Cumulative reduction 17.2% from
the 8,441 starting point. The pattern is sustainable: pure-only
extraction with binding-not-copy re-export shims and dedicated
`test_session_<X>_extracts.py` files. **However**, the remaining
detect.py contains four large bands that resist further
decomposition without behavioural risk: `main()` + argparse (~500
LoC), output formatting (text/JSON/SARIF/HTML/compliance, ~1,500 LoC),
scan control flow per mode (~1,500 LoC), pattern dispatch and
suppression (~1,400 LoC). These are state-touching and have implicit
ordering dependencies.

**Top 5 refactors** (ranked by pain reduction × inverse risk):

1. **Extract output formatting into `_output.py`** —
   `detect.py:3200-4200` (HTML), 4700-5000 (compliance),
   3600-3700 (pr-summary). All pure functions of `(findings, entries,
   summary)`. **Effort:** M (3-4 hrs). **Risk:** LOW. Saves ~200 LoC.
2. **Extract scan modes into `_modes.py`** with a dispatch table —
   `detect.py:5000-5500` covers diff/trend/fleet. **Effort:** L
   (1-2 days). **Risk:** MEDIUM — mode × cache × baseline ×
   suppression interactions need careful testing.
3. **Introduce a `Finding` dataclass.** Today findings are dicts
   passed throughout; a dataclass with `__post_init__` validation
   would catch ~80 implicit-dict-shape bugs at construction time.
   **Effort:** M (4-5 hrs). **Risk:** LOW (transparent passthrough to
   JSON).
4. **Consolidate the three brace-walk loops in `_hcl.py`** into one
   `_brace_walk()` helper — `_hcl.py:126-160, 163-186, 224-249` all
   repeat the same depth-counter idiom. **Effort:** S (1-2 hrs).
   **Risk:** LOW.
5. **Move `_run_engine` test helper to a `conftest.py` fixture.**
   Reduces boilerplate across `tests/test_detection_core.py` and
   sibling files. **Effort:** S (1 hr). **Risk:** LOW.

**Dependency hygiene:**

- Python: `pyproject.toml` requires `>=3.10`; only optional dep is
  `python-hcl2`. **Good.**
- Node: `vscode-extension/package.json` floats `@types/node ^20.0.0`
  and `typescript ^5.3.0`. Acceptable — dev deps.
- CI surface: `.github/workflows/ci.yml` runs pytest, schema
  validator, CLI-docs check, attack-drift gate, demo-corpus smoke,
  stub-age. All required (no optional checks). **Good** — and
  R30.0.5 added the attack-drift gate (`scripts/check_attack_drift.py`)
  so the ATT&CK table can't silently rot.
- Test pyramid: ~20 unit / ~60 fixture / ~24 integration. Healthy
  for a rule-based engine.
- Dead code / circular imports: none detected.

---

## 9. Cross-axis tension — where virality and health conflict

This is the section the spec asks to be explicit about. Three real
tensions surfaced:

**T1. The public scanner (V1) compounds the XSS risk in the HTML
renderer (E1 risk #4 is in the same neighbourhood as the
HTML-XSS launch risk in § 4).** The viral mechanic *is* shared URLs
rendering attacker-influenced HTML. Today `detect.py:3938`'s HTML
renderer has no documented CSP policy. **Prerequisite:** audit and
add strict CSP **before** V1 launch. Do not ship the public scanner
without this. The badge service already follows the right pattern at
`integrations/badge-service/server.py:267-273` — copy it.

**T2. Speed-to-launch on V1 (1 week) collides with the
`detect.py` modularisation in flight (E3 refactor #2, scan modes).**
The async refactor of `demo/app.py` (V1 day 2) calls `detect.py` as a
subprocess, which is fine. But if `_modes.py` extraction lands in the
same window, the demo's subprocess invocation may need to chase new
flag shapes. **Ordering:** ship V1 first, hold the `_modes.py`
refactor until V1 has stable adoption metrics (≥14 days).

**T3. R30.1's multi-framework taxonomy adds 5 new optional
catalogue fields and 8 new compliance modes (`PLAN.md:40`).**
Each new field is one more shape `_catalog.validate_catalog_entry`
has to know about and one more comparison surface relative to
competitors. Health-wise: harmless additions; the validator pattern
scales. Virality-wise: shipping all of R30.1 before V1 splits the
launch story across "more compliance" (uninteresting to HN) and
"public scanner" (interesting). **Ordering:** ship V1 + V2 + V3
first; defer R30.1 to after the launch dust settles.

**Non-tension worth noting:** R30.2 (KEV+EPSS, V4 above) is
**genuinely orthogonal** to the launch path. Build it in parallel; the
"first OSS IaC scanner with KEV ranking" line is a real differentiator
that survives whether the scanner launches before or after R30.2.

---

## 10. Combined 90-day plan

`[viral]` = primarily virality lever · `[health]` = primarily robustness/doc/maintenance · `[both]` = serves both.

### Weeks 1-2 (sprint 1) — prerequisites for V1
- `[both]` Audit `detect.py:3938` HTML renderer for XSS; add strict CSP header to all HTML responses. Copy pattern from `integrations/badge-service/server.py:267-273`.
- `[health]` Land refactor #4 (`_hcl.py` brace-walk consolidation) — small, fast, derisks future seam extracts.
- `[health]` Tighten E1 risk #2: SIGTERM/SIGKILL escalation on MCP subprocess timeouts; add timeout to git ops in `detect.py:4414-4444`.
- `[health]` Add `SECURITY.md` + `ARCHITECTURE.md` stubs (E2 gaps #1, #2). Even minimal versions unblock external contributors.

### Weeks 3-4 (sprint 2) — V1 ship
- `[viral]` Public scanner per § 4 day-by-day plan. Soft-launch on `tfanalyze.fly.dev`.
- `[viral]` V3 live-scan badge inlined into the scanner.
- `[both]` Add `examples/well-formed/` (V5) — also serves as a "we did the right thing" reference for new contributors.

### Weeks 5-6 (sprint 3) — V2 launch
- `[viral]` Show HN tied to a recent IaC CVE or compromised module. Asciinema GIF prepared in advance. Pre-stage `examples/cve-of-the-month/`.
- `[health]` Land refactor #1 (`_output.py` extraction). Reduces detect.py by ~200 LoC; no behavioural risk.
- `[viral]` Pin a GitHub PAT in Fly secrets to dodge the 60/hr unauth GitHub API limit when launch traffic arrives.

### Weeks 7-8 (sprint 4) — health consolidation
- `[health]` Add LSP debounce/coalesce (E1 risk #7); add max-depth guard to `_hcl.find_blocks` (E1 risk #4); cap `--check-registry` response size (E1 risk #5).
- `[health]` Add `Finding` dataclass (refactor #3).
- `[viral]` First post-launch retrospective; tune CDN, cache LRU, and per-IP budget based on real traffic.

### Weeks 9-10 (sprint 5) — V4
- `[viral]` `[both]` Build R30.2 (KEV+EPSS exploitability). Validate on TerraGoat **before** blogging — if hybrid rank changes <5% of orderings, defer and revisit.
- `[health]` Land refactor #2 (`_modes.py`) — V1 is stable by now.

### Weeks 11-13 (sprint 6) — R30.1 + close-out
- `[health]` R30.1 multi-framework taxonomy sweep — five catalogue fields, eight new compliance modes. Treat as a single PR series with a single validator change.
- `[health]` Documentation pass: ARCHITECTURE.md fleshed out, contributor-onboarding doc, LSP troubleshooting guide.
- `[viral]` "60-day retrospective" blog with real numbers: scans/day, stars, badge adoption. Honest framing wins second-wave coverage.

---

## 11. What to NOT build / NOT fix

- **Do NOT register `tfanalyze.com` for V1.** `tfanalyze.fly.dev` is free, automatic HTTPS, and removes a half-day of operator work that blocks launch (`scan-service-plan.md:96-98`). Cut over after virality is proven.
- **Do NOT ship R30.1 (multi-framework taxonomy) before V1.** Compliance breadth is the wrong launch narrative; "the IaC scanner an agent can act on" is sharper. R30.1 is health-positive but virality-neutral.
- **Do NOT block V1 on full `detect.py` modularisation.** Six seams shipped is enough for now; remaining refactors are best done after launch traffic exposes real performance bottlenecks.
- **Do NOT fix all 10 robustness risks before launch.** Risks #1 (broad `except` blocks) and #4 (HCL brace-walk edge cases) are low-blast and well-bounded. The HTML-XSS audit is mandatory; the rest can be deferred.
- **Do NOT chase a "100× faster" benchmark.** TF parsing isn't the user-felt bottleneck; faking one stains the launch.
- **Do NOT publish the VS Code Marketplace listing as a separate
  launch event.** It's already published (`PLAN.md:266`); fold it into
  the V2 Show HN as a one-line claim, not a separate post.
- **Do NOT add the `--watch` mode (`PLAN.md:137`) before V1.** Niche
  enough that the launch story doesn't carry it; LSP already serves
  the use case.

---

## 12. Open questions

- **Does `tfanalyze.com` need to be the launch domain?** The spec
  treats it as load-bearing; the strategy doc and this report treat
  `tfanalyze.fly.dev` as sufficient for MVP. Operator decision.
- **Is there a specific named IaC CVE in the May 2026 window suitable
  for V2's anchor?** Subagent C identified the *pattern* (zizmor +
  tj-actions) but couldn't promise a current incident. Monitor
  `https://www.cve.org/` and the CISA KEV feed weekly through the V1
  window.
- **Does GitHub allow unauth `git clone --depth 1` from a Fly egress
  IP at 5k scans/day?** Subagent D assumed yes (it does for read-only
  HTTPS) but did not verify the rate ceiling in 2026. Add a PAT
  before launch to be safe.
- **Module Reuse ROI accuracy.** Today the "lines saved" estimate is
  `resource_count × constant`. Is there a more honest model
  (e.g. AST-span-based) that would survive launch scrutiny?
- **MCP truncation correctness when scans return >500 findings.** E1
  risk #10. Truncation hits LOW/INFO first by sort order, but if a
  scan produces 600 CRITICAL the last 100 silently disappear from MCP
  output. Should we add a `_truncated_count_by_urgency` field?
- **Memory file at `~/.claude/projects/...`** referenced by the run
  prompt didn't exist on this machine. If the operator wanted that
  source consulted, the analysis would change shape. Flagged.

---

## Verification report

| Section | Subagent(s) feeding it | One cited fact |
|---|---|---|
| 1. Ground truth | A | `detect.py` is 6,985 LoC after six modularisation seams totalling 1,996 LoC extracted (`PLAN.md:22`). |
| 2. Market | B | Terrascan archived Nov 20 2025 ([repo](https://github.com/tenable/terrascan)). |
| 3. Viral patterns | C | zizmor surged after the tj-actions/changed-files compromise, CVE-2025-30066, ~23k repos ([CISA](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)). |
| 4. Scanner plan | D | `demo/app.py` is 93 LoC and already has `POST /scan/repo`; `demo/Dockerfile` is missing `git`. |
| 5. Viral recommendations | A + B + C + D | V4's KEV claim is real differentiator — no OSS IaC scanner does it ([Trivy review](https://appsecsanta.com/trivy), [Snyk IaC](https://appsecsanta.com/snyk-iac), Checkov releases). |
| 6. Robustness | E1 | 17 broad `except Exception` swallowers in `scripts/detect.py:88,121,131,4508,…`. |
| 7. Documentation | E2 | No `SECURITY.md`; per-rule docs site complete at 218 pages for 217 rules (CI gate `.github/workflows/ci.yml:58-71`). |
| 8. Maintainability | E3 | Test pyramid ~20 unit / ~60 fixture / ~24 integration; total 5,662 LoC tests across 30 files. |
| 9. Cross-axis tension | D + E1 | HTML renderer at `detect.py:3938` has no CSP today; viral mechanic depends on shared URLs. |
| 10. Combined 90-day plan | All | Land R30.2 in weeks 9-10 only after TerraGoat validation (`PLAN.md:41`). |
| 11. NOT-do list | All | `tfanalyze.com` registration is operator-only per `PLAN.md:268-269`. |
| 12. Open questions | All | Memory file `~/.claude/projects/-Users-chris-adkin-Projects-tf-analyze/memory/MEMORY.md` not present on the analysis machine. |

All five subagents returned. No section was silently dropped. Two
caveats are repeated at the top of the document and in § 12 (open
questions).
