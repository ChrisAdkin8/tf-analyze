# tf-analyze scan service — TODO

> **Local-only.** Companion to `scan-service-plan.md`. Update as work lands.
> Order is execution order — don't reorder unless dependencies change.

## Week 1 — backend foundation

### Setup + verify the existing Fly app still works

- [ ] `flyctl auth login` (one-time on this machine)
- [ ] `flyctl apps list` — confirm `tf-analyze` exists and `flyctl logs -a tf-analyze` works
- [ ] `flyctl deploy -c demo/fly.toml` against current `main` to verify the existing pipeline is healthy before any changes
- [ ] Curl the deployed app — confirm it responds with the old demo HTML
- [ ] Add a Fly volume for persistent storage:
  ```
  flyctl volumes create scans_data --size 3 --region iad -a tf-analyze
  ```
  3 GB free; mount at `/data` in the next step
- [ ] Update `demo/fly.toml` with the volume mount + bump `memory = "1024mb"` (engine + clones need headroom):
  ```toml
  [mounts]
    source = "scans_data"
    destination = "/data"
  ```
- [ ] Add `git` to the Dockerfile: `RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*`
- [ ] Re-deploy, confirm volume mounted: `flyctl ssh console -a tf-analyze -C "ls -la /data"`

### SQLite schema + helpers

- [ ] Create `demo/db.py` — opens `/data/scans.db`, runs migrations on import
- [ ] Schema:
  ```sql
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    repo TEXT NOT NULL,
    sha TEXT NOT NULL,
    state TEXT NOT NULL,         -- pending|running|done|failed
    score INTEGER,
    grade TEXT,
    findings_count INTEGER,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    error TEXT,
    UNIQUE(owner, repo, sha)
  );
  CREATE INDEX idx_scans_repo ON scans(owner, repo, finished_at DESC);
  ```
- [ ] Add `WAL` mode at startup: `PRAGMA journal_mode=WAL` (concurrent readers + a single writer = no lock contention for our shape)

### API endpoints in `demo/app.py`

- [ ] `POST /scan { url }` →
  - regex-validate URL: `^https://github\.com/([A-Za-z0-9_.-]{1,39})/([A-Za-z0-9._-]{1,100})(?:\.git)?/?$`
  - resolve default branch SHA via `https://api.github.com/repos/<owner>/<repo>` (unauth OK for first 60/hr)
  - `INSERT OR IGNORE` into scans; if existing row is `done`, return 303 to the result URL; if `pending`/`running`, return 202 with status URL
  - schedule background task (asyncio); return `{scan_id, status_url}`
- [ ] `GET /status/<scan_id>` → JSON `{state, progress?, result_url?, error?}` (poll target for the frontend)
- [ ] `GET /scan/<owner>/<repo>/<sha>/` → serve `/data/reports/<sha>/report.html`. 404 if scan never ran; 410 if cache evicted (LRU-removed)
- [ ] `GET /scan/<owner>/<repo>/<sha>/findings.json` → serve cached JSON (lets users wget)
- [ ] `GET /scan/<owner>/<repo>/` (no sha) → 302 to latest scan for that repo (queries DB for max(finished_at)), or 404 if never scanned
- [x] `GET /badge/<owner>/<repo>.svg` → shields.io-format SVG with score + grade. Fallback "no data" badge if no scan exists. Cache-Control: 5 min (let CF cache it). **Shipped R30.15** — `demo/_badge.py` + route in `demo/app.py`; 18 tests in `tests/test_badge.py`.
- [ ] `GET /healthz` → 200 if the engine import succeeds and SQLite read works. Probed by Fly health checks

### Background scan worker

- [ ] Module-level `asyncio.Semaphore(3)` to bound concurrency
- [ ] `async def run_scan(scan_id)` —
  - update `state=running`
  - shallow clone:
    ```python
    proc = await asyncio.create_subprocess_exec(
        "git", "-c", "core.hooksPath=/dev/null",
        "clone", "--depth=1", "--no-tags", "--filter=blob:none",
        f"https://github.com/{owner}/{repo}.git",
        clone_dir,
    )
    ```
  - check repo size after clone — if > 100 MB, abort with `repo_too_large`
  - run engine via subprocess:
    ```python
    await asyncio.create_subprocess_exec(
        sys.executable, "scripts/detect.py",
        "--target", clone_dir,
        "--format", "html",
        "--attack-graph",
        stdout=open(report_html_path, "wb"),
    )
    ```
  - re-run with `--format json` to capture summary block
  - parse JSON, update scans row: `state=done, score, grade, findings_count, finished_at`
  - clean up clone dir (keep only `/data/reports/<sha>/`)
- [ ] Wrap entire run_scan in `asyncio.wait_for(..., timeout=60)` — 60-second hard cap
- [ ] On any exception: set `state=failed, error=<str(e)>[:500]`. Surface in `/status` response
- [ ] Process-level scan queue: on app startup, scan SQLite for any rows in `state in (pending,running)` left over from a crash. Mark them failed.

### Acceptance gate for week 1

- [ ] `curl -X POST tfanalyze.com/scan -d 'url=https://github.com/ChrisAdkin8/tf-analyze' -H 'Content-Type: application/x-www-form-urlencoded'` returns 200 + scan_id
- [ ] Polling `/status/<id>` returns `done` within 30 seconds
- [ ] `/scan/ChrisAdkin8/tf-analyze/<sha>/` returns the HTML report
- [x] `/badge/ChrisAdkin8/tf-analyze.svg` returns a valid SVG with the right score (after first `/scan/.../` visit populates the cache)
- [ ] Re-submitting the same URL within 1 minute returns the cached scan_id (no re-scan)
- [ ] Submitting a non-GitHub URL returns 400 with a helpful message
- [ ] Submitting a private/nonexistent repo returns 404 with a helpful message

## Week 2 — frontend + worker hardening

### Single-page form (replaces `demo/index.html`)

- [ ] H1: "Scan any Terraform repo for security issues"
- [ ] Subhead: "Static + plan-time analysis. Attack-graph reasoning. Adversarial narratives. Free for public repos."
- [ ] Form: large URL input + Submit. Pre-filled placeholder: `https://github.com/terraform-aws-modules/terraform-aws-vpc`
- [ ] Below the fold: three feature blurbs (attack graph, narratives, module reuse) with screenshots; install CTAs (VS Code extension + GitHub Action) at the bottom
- [ ] Form submission: client-side fetch → POST `/scan` → poll `/status` → 302 to result URL
- [ ] Loading state: animated "Cloning… Analysing… Building report…" so users don't bounce after 5 seconds
- [ ] Error states: 400 (bad URL, inline error message), 429 (rate limited, "try again in N min"), 500 (engine error, suggests filing an issue)

### Results page (`/scan/<owner>/<repo>/<sha>/`)

- [ ] **Score banner at top** — big number + grade letter, coloured by tier (green/blue/amber/orange/red). Include the absolute scan timestamp for trust.
- [ ] **Embedded attack-graph SVG** below the score
- [ ] **Top 10 findings** with adversarial narratives (those that have them)
- [ ] **Permalink copy button** — copies current URL to clipboard
- [ ] **Share buttons** — Twitter, LinkedIn, Mastodon, copy-as-markdown (for putting in PRs)
- [ ] **Embed-the-badge code block** — pre-formatted markdown line for the README
- [ ] **CTAs at the bottom** — "Get this on every PR" → GitHub Action; "Get live diagnostics in your editor" → VS Code Marketplace

### Worker hardening

- [ ] Test against deliberate bad-repos:
  - 1 GB repo → `repo_too_large`
  - Repo with no .tf files → 0 findings, score 100, render successfully
  - Repo with malformed HCL → engine should not panic; surface as "0 valid Terraform files"
  - Repo with submodules → don't recurse (`--no-tags` already implies, but verify)
  - Private repo (404 on the API call) → friendly error
- [ ] LRU cache eviction job: periodic asyncio task, runs every hour, evicts oldest scans when `/data/reports` exceeds 2 GB
- [ ] Per-IP rate limit at app layer: `slowapi` package or rolling-window dict in memory (10 scans/hour per IP, anon)

### Acceptance gate for week 2

- [ ] Frontend works in Safari + Chrome + Firefox
- [ ] Scanning the project's own repo (`ChrisAdkin8/tf-analyze`) produces a clean report (zero CRITICAL findings is the dogfood signal)
- [ ] Scanning `examples/terragoat` via its public repo URL produces ~270 findings and a D grade
- [ ] Lighthouse score ≥ 90 (frontend should be lean — no JS framework, single CSS file)

## Week 3 — security, observability, polish

- [ ] Cloudflare in front:
  - Add a CNAME for the Fly app
  - Enable "Always Use HTTPS"
  - Set page rule: cache `/scan/*` at edge for 1 hour, `/badge/*.svg` for 5 minutes
  - Enable bot fight mode (free tier; blocks the most basic crawler abuse)
- [ ] Per-IP rate limit at Cloudflare edge: 30 req/min per IP across all endpoints
- [ ] Structured JSON logs:
  ```python
  log.info("scan", extra={
      "owner": owner, "repo": repo, "sha": sha,
      "duration_ms": dur_ms, "findings": n, "cache_hit": False,
      "ip": request.client.host,
  })
  ```
  Pipe to Fly's built-in log stream (no extra service)
- [ ] Prometheus-format `/metrics` endpoint (optional but cheap; add `prometheus-client`):
  - `tfanalyze_scans_total{state="done|failed"}`
  - `tfanalyze_scan_duration_seconds` histogram
  - `tfanalyze_cache_hits_total`
  - `tfanalyze_active_scans` gauge
- [ ] HTML escape audit on report rendering (manual pass through the engine's HTML output for any user-supplied content paths)
- [ ] CSP header on every response (`default-src 'self'; img-src 'self' data: https://img.shields.io; ...`)

## Week 4 — soft launch

- [ ] Update repo `README.md` first line: "🌐 Try it: [tfanalyze.com](https://tfanalyze.com)"
- [ ] Embed the badge in `README.md`
- [ ] Add a "🌐 Web scanner" entry in the Quickstart (between Docker and VS Code) — one-line: paste URL, get report, no install
- [ ] Record the 90-second demo video — last 5 seconds shows pasting a URL into the web scanner and getting a report
- [ ] Pre-launch checklist:
  - [ ] All week 1–3 acceptance gates green
  - [ ] Cloudflare in front, rate limits configured
  - [ ] Health check passes consistently for 24 hours
  - [ ] Run a manual load test (`hey -z 10m -q 1 -c 5 'POST /scan' …`) — verify no scan failures, no memory leak, no disk fill
- [ ] Soft launch: post to Hacker News "Show HN" Tuesday 9am PT
- [ ] Mirror to Lobsters, r/Terraform, r/devops on the same day
- [ ] Monitor Fly logs for 6 hours post-launch; have a rollback plan (`flyctl deploy --image <prior_sha>`)

## Pre-MVP exit criteria

Treat the launch as complete when **all** of:

- [ ] System has survived 1k+ unique scans without intervention
- [ ] p99 scan latency < 30 seconds
- [ ] Failure rate < 5%
- [ ] At least 10 unique referrers in the access logs (proxy: organic discovery is happening)

## Post-MVP backlog (don't start until exit criteria are met)

- [ ] Custom domain (`tfanalyze.dev` ~$15/yr or `.com` ~$12/yr)
- [ ] GitHub OAuth + private repo scanning ($5/mo subscription tier)
- [ ] Comparison view: `/diff?from=<sha1>&to=<sha2>`
- [ ] Scheduled re-scans (webhook on push)
- [ ] GitLab + Bitbucket support
- [ ] State-of-IaC quarterly report — uses this service's batch-scan capability
- [ ] Trivy plugin (gated on the single-binary distribution, not on this service)

## Anti-goals (don't build, even if asked)

- ❌ User accounts before they're forced by a private-repo tier
- ❌ Email subscriptions to "your repo's score this week"
- ❌ Slack/Discord webhooks
- ❌ A REST API beyond the four endpoints listed in week 1
- ❌ Browser extension (separate project; don't conflate)
- ❌ Local-first PWA mode
- ❌ Markdown vs HTML output toggle (`--format` is the engine's job, not the service's)

Each one is reasonable on its own. None of them belong in MVP.
