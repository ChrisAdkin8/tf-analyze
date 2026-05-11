# tf-analyze public scan service — plan

> **Local-only.** Strategy doc, gitignored alongside `virality-plan.md`.

## Executive summary

Extend the existing `demo/` FastAPI app into a public web scanner: paste a GitHub repo URL, get a permalink to a styled report. **Cheapest viable infrastructure: Fly.io's existing `tf-analyze` machine, scale-to-zero, ~$0–5/month at first-thousand-users traffic.** No new infrastructure to provision; we already have the deployment shape, the Docker image, and the scan engine.

This is the load-bearing feature from `virality-plan.md` — every other item compounds from it (badge service, demo video CTA, state-of-IaC report data pipeline). MVP at **week 4** of the 90-day plan.

## Scope (MVP)

**In:**
- `tf-analyze.fly.dev/scan/<owner>/<repo>` — paste a public GitHub URL, get a scored report
- Public GitHub repos only (no auth, no private repos)
- Cache keyed on commit SHA — re-scanning unchanged repos is free
- Permalink per scan — sharable URL is the viral mechanic
- HTML report inline, JSON report downloadable
- Score badge SVG at `/badge/<owner>/<repo>.svg` (couples to scan results)
- Rate limit by IP (Fly's edge or a cheap Cloudflare proxy)

**Out (defer to post-MVP):**
- User accounts, OAuth, private repos
- Scheduled re-scans
- Per-user history / dashboards
- Subscription / billing
- Custom domain (use `tf-analyze.fly.dev` until proven; `tfanalyze.dev` ($15/yr) once metrics justify)
- GitLab / Bitbucket support
- Comparison views (this scan vs. prior scan)
- API for programmatic scans (just point users at the engine + Action)

The discipline here is "what does the viral mechanic *require*?" — and the answer is just **paste URL → see report → share URL**. Everything else is a feature gate that delays the launch.

## Architecture

```
┌─────────────────┐
│  Browser form   │  POST /scan { url: github.com/owner/repo }
└────────┬────────┘
         ▼
┌─────────────────────────────────────────────────────────────┐
│  Fly machine (existing tf-analyze, 1 GB, scale-0)           │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐ │
│  │  FastAPI     │──▶│  scan queue  │──▶│  worker (asyncio)│ │
│  │  /scan       │   │  (in-proc)   │   │  - resolve SHA   │ │
│  │  /status/<id>│   │              │   │  - shallow clone │ │
│  │  /scan/<...> │   │              │   │  - run detect.py │ │
│  │  /badge/...  │   │              │   │  - persist HTML  │ │
│  └──────────────┘   └──────────────┘   └──────────────────┘ │
│         │                                          │         │
│         ▼                                          ▼         │
│  ┌──────────────┐                       ┌──────────────────┐ │
│  │  SQLite      │                       │  /data volume    │ │
│  │  scan_meta   │                       │  reports/<sha>/  │ │
│  │  (1 file)    │                       │  - report.html   │ │
│  └──────────────┘                       │  - findings.json │ │
│                                         │  - graph.svg     │ │
│                                         └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**Why monolith for MVP:** complexity floor is the engine itself. Adding a separate worker process, a queue service, a database server — each one is more failure surface than queue depth saved. Single Python process with `asyncio.Semaphore(3)` to bound concurrent scans is enough for the first 10k scans.

When to split: when scan queue depth p99 exceeds 30 seconds, or when a single scan starts blocking unrelated requests. Both signals show up in Fly metrics; nothing to instrument upfront.

## Infrastructure: cheapest viable

### Compute — Fly.io

The existing `tf-analyze` Fly app is already optimised for this:
- `auto_stop_machines = "stop"` + `min_machines_running = 0` → costs **$0** when nobody's scanning
- Cold-start ~3-5 seconds (the engine needs to load the catalogue) — acceptable for an interactive scan UX with a polling status page
- 512 MB RAM is enough for the engine + a single 100 MB shallow clone
- Scaling: at $1.94/month for shared-cpu-1x, even sustained 24/7 traffic is <$10/month

**Pricing reality check:**
- Fly's free allowance: 3 shared-cpu-1x VMs free (effectively the existing app's spot)
- Inbound bandwidth: free
- Outbound: 100 GB/mo free, then $0.02/GB
- Volumes: 3 GB free, then $0.15/GB-mo

Even if 100k people scan a single 100 MB repo each, that's 10 TB inbound (free), no clones cached so 10 TB outbound clones from GitHub (also free for the runner — GitHub doesn't charge clone bandwidth), and ~10 GB of cached HTML reports stored on the volume (~$1/mo). The engine itself does the heavy lifting on the runner; we never re-egress the clone.

**Anti-pattern to avoid:** building this on Lambda. The 15-min execution cap is fine but the cold-start penalty + lack of persistent FS for the report cache + per-invocation cost on a tool whose viral mechanic is "many strangers each running it once" makes Lambda strictly more expensive at every traffic level above zero.

### Storage — SQLite + Fly volume

For MVP scope (cache scan metadata, store HTML reports), there's no reason to introduce a separate database server.

- **`scans.db` (SQLite, on the Fly volume):** one row per (owner, repo, commit SHA). Columns: `id`, `repo`, `sha`, `score`, `grade`, `findings_count`, `scanned_at`, `report_path`. ~50 bytes per row, 1 GB stores ~20M scans.
- **`/data/reports/<short_sha>/`:** the rendered report.html, findings.json, attack-graph.svg. Pre-rendered at scan time; serving is a static-file response.

When to migrate: when a single SQLite write blocks reads (we'll see this as request latency above ~100ms p99). For our use case, that probably never happens — writes are batched per scan completion, not per request.

### Domain — `tf-analyze.fly.dev` for now

Free, automatic HTTPS, perfectly fine for MVP. Move to a paid `.dev`/`.com` after proving virality. The 90-second demo video can use `tf-analyze.fly.dev` in the CTA without harming the message.

### CDN / DDoS — Cloudflare in front (free tier)

Fly's edge handles HTTPS but Cloudflare's free tier adds:
- Caching for the static report HTML (`/scan/<...>` URLs become free-tier-cacheable; the badge SVG too)
- Rate limiting for scan requests (10/min per IP free, prevents the most basic abuse)
- DDoS protection at no cost

Setup: point a Cloudflare DNS A record at the Fly IP, enable "proxy through Cloudflare" (orange cloud). Done.

### GitHub API — unauth → token

For looking up the default branch's HEAD SHA:
- Unauth: 60 req/hour per IP. Plenty for MVP.
- With a personal-access token in env: 5,000/hour. Add when traffic warrants.
- For private repos (post-MVP): user OAuth.

## Cost model

| Phase | Monthly traffic | Cost |
|---|---|---|
| MVP (first 30 days) | 0–500 scans/day | **$0** — Fly free tier, no domain |
| Validated (months 2–3) | 500–5k scans/day | **$1–5** — Fly volume + occasional active machine |
| Scaled (months 4–6) | 5k–50k scans/day | **$15–40** — second machine, paid domain ($15/yr ÷ 12), Cloudflare still free |
| Hypothetical viral month | 100k scans/day | **$80–150** — multiple machines, mostly outbound bandwidth past the free 100 GB |

The cost curve only steepens past viral-month territory. We can profitably run this out of beer money for a year before having to think about monetisation.

## Implementation order

### Week 1 — backend foundation

Reusing `demo/app.py`:

1. New endpoint `POST /scan`: validates URL shape, resolves default branch SHA via GitHub API, returns `{scan_id, status_url}`.
2. New endpoint `GET /status/<scan_id>`: returns `{state: pending|running|done|failed, progress, result_url}`.
3. New endpoint `GET /scan/<owner>/<repo>/<sha>/`: serves the cached HTML report. 404 if not yet scanned.
4. New endpoint `GET /badge/<owner>/<repo>.svg`: returns the latest-scan score as a shields.io-format badge. Falls back to "scan now" prompt if no scan exists.
5. SQLite schema + initial migration.
6. Background scan worker as an asyncio task. Bounded by `Semaphore(3)`. Implements: shallow clone, run `detect.py`, persist outputs, update DB.

### Week 2 — frontend + worker hardening

7. Replace `demo/index.html` with a single-page form that posts to `/scan`, then polls `/status/<id>` and redirects on completion. Server-rendered, no JS framework.
8. Results page (`/scan/<owner>/<repo>/<sha>/`): big score banner, attack-graph SVG inline, top 10 findings with adversarial narratives, compliance summary, install CTAs (VS Code extension + GitHub Action).
9. Permalink "copy" button + share buttons (Twitter / LinkedIn / Mastodon).
10. Worker hardening: 60-second scan timeout, max 100 MB clone size, abort + report "repo too large" gracefully.
11. Error pages — 404 (scan never run), 410 (cache evicted), 429 (rate limited), 500 (engine crashed; surface stderr).

### Week 3 — caching, security, observability

12. Cache eviction policy: LRU on disk usage > 2 GB. Re-scanning evicts the oldest scan.
13. Input validation hardening: regex on `owner`/`repo` (`[A-Za-z0-9_.-]{1,39}` and `{1,100}`), reject anything else with 400. Path traversal proofing on the disk paths.
14. Rate limiting: per-IP (Cloudflare) + per-IP at the app layer (10 scans/hour anon).
15. Structured logging: every scan request logs (URL, SHA, scan duration, finding count, cache hit/miss). Pipe to Fly's built-in log stream.
16. Health endpoint `/healthz` → 200 if the engine import succeeds.
17. Cloudflare in front of `tf-analyze.fly.dev` (or whatever domain).

### Week 4 — soft launch

18. Submit to one curated link aggregator (Hacker News "Show HN" Tuesday 9am PT, or Lobsters).
19. Update README with "🌐 Try it: tf-analyze.fly.dev" line at the top.
20. Add the badge to the README itself: `[![tf-analyze](https://tf-analyze.fly.dev/badge/ChrisAdkin8/tf-analyze.svg)](...)`.
21. Demo video CTA points at the live URL.
22. **Hard cap on the launch:** if the soft launch fires and the system survives 1k unique scans, declare MVP complete and move to week 5+ items from the broader virality plan.

## Security considerations

| Surface | Threat | Mitigation |
|---|---|---|
| Repo URL input | Path traversal, protocol confusion, internal-network SSRF | Strict regex on owner/repo segments; only `https://github.com/<owner>/<repo>` accepted; explicit `git clone --depth=1` with `https://` URL constructed from validated segments — never user-supplied |
| Repo content | Repo with malicious post-checkout hooks | `git clone --depth=1 --no-tags --filter=blob:none` + `git -c core.hooksPath=/dev/null clone ...` — run hooks disabled |
| Repo size | Repo with TB of content / billion files | Pre-clone size check via GitHub API; `--depth=1` + per-clone disk quota; abort if size > 100 MB after clone |
| Engine | detect.py crashes on malformed HCL | Already handled — catalogue parses with try/except; engine never panics. But: wrap in `asyncio.wait_for()` with a 60-second timeout |
| Rate limiting | Same user re-scans same repo 100x to drive up server cost | Cache by SHA (re-scan returns cached result, free); 10 scans/hour per IP via Cloudflare |
| DoS via stuck scans | Worker hangs, queue fills | `Semaphore(3)` + per-scan timeout + cancel-on-timeout |
| XSS via finding output | Engine emits unsanitised content into HTML | `--format html` already escapes via Jinja2/template; one-time audit before launch |
| Information disclosure | Cached scan accidentally serves another user's content | Filesystem layout keyed strictly on `<owner>/<repo>/<sha>` with no per-user namespace; no PII collected, all repos are public |

## Open questions / decisions to defer

1. **Custom domain timing.** Move from `tf-analyze.fly.dev` to a paid domain when? Probably after first 1k unique scans. ROI: better share-URL aesthetics, brand defensibility.
2. **GitHub OAuth for higher API rate limits.** Required when the unauth 60/hour limit starts capping. Add on signal, not on speculation.
3. **Caching tier above SQLite.** Maybe Cloudflare KV when scan metadata exceeds 100k rows. Defer until needed.
4. **Subscription tier.** If usage takes off, "Scan private repos for $5/mo" is the obvious play. Don't build it until at least one user explicitly asks.
5. **Comparison view (this scan vs. that scan).** A "see what changed" view is a natural follow-up but isn't required for the viral loop. Defer to v2.
6. **Webhook integrations.** "Re-scan automatically when this repo gets a push." Cool but adds complexity. Defer.
7. **Should we clone via the GitHub API's tarball endpoint instead of `git clone`?** Faster (no .git overhead), but loses commit-SHA metadata. Probably worth using for the actual scan and looking up SHA separately.

## Why not the alternatives

| Alternative | Why not |
|---|---|
| **Cloudflare Workers + R2** | Workers can't run Python or `git clone`. Need a separate worker. Cost saving doesn't materialise. |
| **AWS Lambda** | 15-min cap is fine but cold-start + per-invocation cost dominate at our traffic shape (many strangers each running once). Strictly more expensive than Fly above 0 RPS. |
| **GitHub Actions as the worker** | Tempting (free for public repo workflows). But: artifact access requires GitHub authentication, ruining the "stranger pastes URL, sees report" UX. Add to v2 backlog if a private-repo tier ever ships. |
| **Self-hosted on a Hetzner VPS** | $4/mo for a 2 GB / 2 vCPU box, more headroom than Fly's free tier. But: ops burden, no auto-scale, no built-in HTTPS/edge. Net: more expensive once ops time is priced in. |
| **Vercel / Netlify Functions** | Same Lambda problems plus opinionated frontend frameworks we don't need. |

## What this plan deliberately does *not* do

- **Doesn't introduce a queue/database/cache infrastructure.** Single Python process + SQLite + filesystem. When something blocks, split it then. Premature splitting is the most common cause of dev-tool startups dying before their first user.
- **Doesn't build a content management system around the reports.** Reports are static HTML pre-rendered at scan time. The cache directory IS the CMS.
- **Doesn't add observability beyond Fly's built-in logs + a `/healthz` endpoint.** You can't tune what you can't measure, but you can also drown in metrics. Add Prometheus / Grafana when there's a real performance question to answer.
- **Doesn't try to be a tfsec/checkov killer in v1.** Just be the *only* tool with a public scan URL. That's the wedge.
