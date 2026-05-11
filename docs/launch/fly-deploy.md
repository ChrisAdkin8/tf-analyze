# Fly.io deployment for the web demo

The web demo (`demo/`) is a FastAPI app + CodeMirror 6 editor + D3
attack-graph visualiser. It is the load-bearing virality surface
(`/scan/<owner>/<repo>` permalinks) — see
[`scan-service-plan.md`](scan-service-plan.md).

- **Canonical URL:** https://tfanalyze.com/ (also `https://www.tfanalyze.com/`)
- **Fly fallback hostname:** https://tf-analyze.fly.dev/ (kept alive automatically; old shared links still resolve)
- **Fly app:** `tf-analyze` (org `personal`, region `iad`)
- **Volume:** `tfanalyze_scan_cache` (1 GB, auto-created from `[[mounts]]`)
- **Image source:** repo-root build context, `demo/Dockerfile`

## One-time setup

```sh
brew install flyctl
flyctl auth login
```

Optionally grab a CI token:

```sh
flyctl auth token
# Save as FLY_API_TOKEN secret in the repo settings if wiring to GHA.
```

## Routine redeploy

The app is already created and configured. Day-to-day, you only run:

```sh
# From the REPO ROOT — not from demo/.
flyctl deploy --config demo/fly.toml
```

That's it. Fly reads `demo/fly.toml`, builds the image with the repo
root as context, pushes to the registry, and rolls the running machine.
Auto-stop kicks back in when traffic drains; cost stays at $0.

### Why deploy from the repo root

`demo/Dockerfile` copies repo-root paths:

```dockerfile
COPY demo/requirements.txt requirements.txt
COPY scripts/detect.py scripts/detect.py
COPY scripts/_*.py scripts/         # all engine helpers
COPY catalog/ catalog/
COPY demo/app.py demo/index.html demo/
```

If you `cd demo && flyctl deploy`, the build context is just `demo/`
and every `COPY scripts/...` / `COPY catalog/...` fails with
`failed to compute cache key: ... not found`. The `--config` flag
keeps the config path pointed at the subdir while leaving the build
context at the root, which is the only way the Dockerfile resolves.

## First deploy (from scratch)

If the app is ever destroyed and you need to recreate it:

```sh
# 1. Reserve the app name (global namespace across all Fly users).
flyctl apps create tf-analyze --org personal

# 2. Deploy. The [[mounts]] block in fly.toml auto-creates the
#    tfanalyze_scan_cache volume on the first machine boot.
flyctl deploy --config demo/fly.toml

# 3. Verify.
flyctl status -a tf-analyze
curl -sI https://tfanalyze.com/   # GET returns 200; HEAD returns 405 (Flask)
```

There are no secrets to set — the app reads no env-supplied
credentials. Rate-limit, payload-cap and scan-timeout values are
compiled-in constants in `demo/app.py`; if you need to tune them,
change the source and redeploy.

## Custom domain

`tfanalyze.com` is the canonical user-facing URL. Apex and `www`
certificates are both registered on the `tf-analyze` app:

```sh
flyctl certs list -a tf-analyze
# Expected: tfanalyze.com and www.tfanalyze.com, both with status "Ready".
```

If you ever need to re-add them (e.g. after a future rename):

```sh
flyctl certs add tfanalyze.com -a tf-analyze
flyctl certs add www.tfanalyze.com -a tf-analyze
flyctl certs show tfanalyze.com -a tf-analyze     # confirms LE issuance
flyctl certs show www.tfanalyze.com -a tf-analyze
```

DNS records (set at the registrar):

| Type | Name | Value |
|---|---|---|
| `A`    | `@`   | `66.241.124.72` |
| `AAAA` | `@`   | `2a09:8280:1::114:2170:0` |
| `A`    | `www` | `66.241.124.72` |
| `AAAA` | `www` | `2a09:8280:1::114:2170:0` |

Run `flyctl ips list -a tf-analyze` to re-check IPs; the dedicated
IPv6 is stable, the shared IPv4 belongs to Fly and may rotate
(uncommon, but worth knowing).

## Renaming the app

Fly does not support in-place renames — the app name *is* the
hostname. To change the URL:

```sh
# 1. Edit demo/fly.toml — change `app = "<old>"` to `app = "<new>"`.
# 2. Reserve the new name.
flyctl apps create <new> --org personal

# 3. Deploy. A fresh tfanalyze_scan_cache volume is created on the
#    new app from [[mounts]] initial_size.
flyctl deploy --config demo/fly.toml

# 4. Smoke-test https://<new>.fly.dev/.
# 5. Once happy, destroy the old app. The scan cache on the old
#    volume is per-SHA — it will rebuild on demand on the new app.
flyctl apps destroy <old>
```

The volume does *not* migrate. The scan cache is a per-SHA
opportunistic cache (`/var/cache/tf-analyze/<owner>_<repo>_<sha>.json`),
so the new app starts cold and warms back up after the first scan
of each repo.

## Post-deploy validation

```sh
# 1. UI loads.
curl -s https://tfanalyze.com/ | grep -c '<title>tf-analyze'

# 2. /scan/hcl returns valid JSON with both `graph` and `findings`.
curl -s -X POST https://tfanalyze.com/scan/hcl \
  -H 'Content-Type: application/json' \
  -d '{"hcl": "resource \"aws_s3_bucket\" \"x\" { bucket = \"x\" }"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
                print('score:', d['summary']['score']); \
                print('findings:', len(d['findings'])); \
                print('graph nodes:', len(d['graph']['nodes']))"

# 3. Rate limit (10 req / 60 s per IP).
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    https://tfanalyze.com/scan/hcl \
    -H 'Content-Type: application/json' -d '{"hcl": ""}'
done
# Expected: ten 4xxs (400 on empty HCL) then two 429s.

# 4. Public permalink (clone + scan + cache).
curl -sI https://tfanalyze.com/scan/terraform-aws-modules/terraform-aws-vpc
# Expected: 200 once the clone completes (~5–10 s cold, instant on cache hit).
```

## Hard caps and pricing

`demo/fly.toml` pins one `shared-cpu-1x` machine with 1 GB RAM and a
1 GB volume. With `auto_stop_machines = "stop"` and
`min_machines_running = 0`, the app idles at $0 and ramps to a few
dollars/month under sustained traffic.

Compiled-in safety nets (see `demo/app.py`):

- 10 req / 60 s per-IP rate limit
- 30 s subprocess timeout on the scanner
- 60 s subprocess timeout on the shallow clone
- 50 KB cap on pasted HCL
- 500 `.tf` file cap and 50 MB content cap on cloned repos
- Owner/repo strings validated against strict regex before reaching `git clone`

## Logs and troubleshooting

```sh
flyctl logs -a tf-analyze                                # live stream
flyctl logs -a tf-analyze --no-tail | tail -50           # last 50 lines
flyctl ssh console -a tf-analyze                         # shell into the machine
flyctl ssh console -a tf-analyze -C "ls /var/cache/tf-analyze | wc -l"
```

Common failure modes:

| Symptom | Diagnosis | Fix |
|---|---|---|
| Build fails with `COPY ... not found` | Deployed from `demo/`, not repo root | Re-run from repo root with `--config demo/fly.toml` |
| `Request failed: node not found: undefined` in the browser | D3 wants `{source,target}` but engine emits `{from,to}` | Already fixed in `demo/index.html`; redeploy |
| Empty attack graph | Frontend reading wrong JSON key | `demo/index.html` reads `data.graph` (not `data.attack_graph`) — already correct as of May 2026 |
| `Could not find App` from `flyctl status` | App was destroyed or `--org` mismatch | Re-run `flyctl apps create tf-analyze --org personal` |
| 503 on first request after long idle | Cold start (machine resumed from stop) | Normal; ~3–5 s as the engine catalogue loads |

## Cache hygiene

The 1 GB `tfanalyze_scan_cache` volume holds one JSON file per
`(owner, repo, sha)` tuple (~50 KB each → headroom for ~20k entries).
If it ever fills up:

```sh
flyctl ssh console -a tf-analyze \
  -C "find /var/cache/tf-analyze -mtime +30 -delete"
```

Entries are immutable per SHA, so eviction is just "delete the oldest" —
no consistency hazard.

## Rollback

```sh
flyctl releases -a tf-analyze                  # list deploys, copy a prior image tag
flyctl deploy --image registry.fly.io/tf-analyze:deployment-<sha>
```

The image tags are visible in `flyctl releases`; each successful deploy
prints the new tag. Roll forward, not back, unless you genuinely need
the old image — re-deploying a known-good `main` commit is usually
faster.

## When to graduate off Fly

The plan in `scan-service-plan.md` projects ~$0–5/month at the
first-thousand-users tier. Signals to revisit infrastructure:

- Scan queue depth p99 > 30 s (Fly metrics) → split worker process
- Sustained outbound > 100 GB/month → consider Cloudflare in front
- Single-region latency complaints from EU/APAC users → add a second
  Fly region (the `[[mounts]]` model gives you one volume per region)

None of these are imminent. Stay monolith until the metrics force the move.
