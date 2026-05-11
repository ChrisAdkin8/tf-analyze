# tf-analyze public scanner — `tfanalyze.com/scan/<owner>/<repo>`

A FastAPI app exposing three surfaces:

| Route | Purpose |
|---|---|
| `GET /` | Paste-and-scan UI (existing demo) |
| `POST /scan/hcl` | JSON body `{hcl: "..."}` — used by the index editor |
| `POST /scan/repo` | JSON body `{repo: "<url>"}` — legacy API |
| **`GET /scan/<owner>/<repo>`** | **Public permalink (R30.14).** Resolves HEAD, scans, returns styled HTML. Cached by commit SHA. |
| `GET /scan/<owner>/<repo>.json` | Machine-readable form of the same permalink. |
| `GET /healthz` | Liveness probe |

The public permalink is the **load-bearing virality surface** — every
share is an organic referral. Pages are cached at `/var/cache/tf-analyze/`
(a mounted Fly volume) so two strangers hitting the same URL share a
single scan.

## Local development

```sh
pip install -r demo/requirements.txt
TFA_SCAN_CACHE_DIR=/tmp/tfa-cache uvicorn demo.app:app --reload --port 8080
# Then:
curl -s http://localhost:8080/scan/terraform-aws-modules/terraform-aws-vpc | head -20
```

## Deploy to Fly.io

Live at **https://tf-analyze.fly.dev/**. The full runbook (first-deploy,
redeploy, renaming, troubleshooting) lives in
[`docs/launch/fly-deploy.md`](../docs/launch/fly-deploy.md). The
short version, run from the repo root:

```sh
flyctl auth login                                                  # one-time
flyctl deploy --config demo/fly.toml --dockerfile demo/Dockerfile  # every release
```

**Build context matters.** The `Dockerfile` references repo-root paths
(`scripts/`, `catalog/`, `demo/`), so `flyctl deploy` must be invoked
from the project root — never from inside `demo/`. The `--config` and
`--dockerfile` flags point at the demo subdir while keeping the build
context at the root.

The `tfanalyze_scan_cache` volume is auto-created on first deploy from
`[[mounts]] initial_size = "1gb"` in `fly.toml` — no separate
`flyctl volumes create` step needed.

After the first deploy, point a custom domain if/when desired:

```sh
flyctl certs add tfanalyze.com                     # one-time, points DNS
```

## Hardening

* Per-IP sliding-window rate limit (10 req / 60s).
* 60s subprocess timeout on each clone; 30s on the scanner.
* Owner / repo names validated against strict regex before being passed
  to `git clone`.
* Public clones use `--depth 1 --single-branch --filter=blob:limit=1m`
  to bound resource usage.
* Repositories with >500 `.tf` files or >50 MB content are refused
  (those should use the GitHub Action surface).
* Scan results are cached on disk by `(owner, repo, sha)` tuple — no
  user-controlled inputs reach the filesystem path verbatim; `_` is
  the separator and the regex above prevents `..` / slashes.
* The HTML report escapes every interpolated value via `html.escape`.

## Cache layout

```
/var/cache/tf-analyze/
├── terraform-aws-modules_terraform-aws-vpc_a1b2c3...json
├── hashicorp_terraform-elastic-stack_d4e5f6...json
└── ...
```

Entries are immutable per SHA. Re-cloning happens only when the upstream
default branch advances. The volume is sized at 1 GB — at ~50 KB per
cached scan that's ~20k entries before any eviction is needed; if it
fills up, `flyctl ssh console -C "find /var/cache/tf-analyze -mtime +30 -delete"`.

## Why a permalink and not a form?

Static URLs are shareable. Posting
`https://tfanalyze.com/scan/terraform-aws-modules/terraform-aws-vpc` in
Slack / Twitter / HN is a one-click action; visitors land on a
pre-rendered report with an Open Graph card showing the score and grade.
Form-based scanners ask the visitor to do work first; nobody shares
those.
