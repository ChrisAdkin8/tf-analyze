# Fly.io deployment for the web demo

The web demo (`demo/`) is a FastAPI app + CodeMirror 6 + d3 attack
graph. `demo/Dockerfile` and `demo/fly.toml` already exist; this is
the operator runbook for the first deploy.

## One-time

```sh
brew install flyctl
flyctl auth login
```

Get a `flyctl` API token if you want to wire the deploy into CI:

```sh
flyctl auth token
# Save as FLY_API_TOKEN secret in the repo settings.
```

## First deploy

```sh
cd demo
flyctl launch --name tf-analyze-demo --region lhr --no-deploy
flyctl secrets set RATE_LIMIT_PER_MIN=10 SCAN_TIMEOUT_S=30 MAX_PAYLOAD_KB=50
flyctl deploy
flyctl status                # confirm the app is healthy
flyctl ips list              # note the public IPv4 + IPv6
```

## Domain

```sh
# Add an A + AAAA record at tf-analyze.dev (or whatever subdomain).
flyctl certs add demo.tf-analyze.dev
flyctl certs show demo.tf-analyze.dev   # confirms LE issuance
```

Once the cert resolves (≤ 5 minutes), update README hero CTA to
"Try the demo" pointing at the public URL.

## Post-deploy validation

```sh
# Smoke-test the JSON API
curl -X POST https://demo.tf-analyze.dev/scan/hcl \
  -H 'Content-Type: application/json' \
  -d '{"hcl": "resource \"aws_iam_user\" \"x\" { name = \"admin\" }"}' \
  | jq '.summary.score'
# Expected: a number in [0, 100], typically ≤ 90 for that input.

# Rate limit
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    https://demo.tf-analyze.dev/scan/hcl \
    -H 'Content-Type: application/json' \
    -d '{"hcl": ""}'
done
# Expected: ten 200s then two 429s.
```

## Resource limits

The demo intentionally caps payload size, scan time, and per-IP rate
to prevent abuse. Defaults in `demo/app.py`:

- `RATE_LIMIT_PER_MIN=10` per IP
- `SCAN_TIMEOUT_S=30`
- `MAX_PAYLOAD_KB=50`
- Repo-scan validation: only `github.com` and `gitlab.com` URLs accepted

These are env vars; bump for a presentation, then `flyctl secrets set`
them back to defaults afterward.

## Cost ceiling

`fly.toml` pins `[[vm]]` to a single shared-cpu-1x instance with
256 MB RAM, scaling to zero. Free-tier eligible at this size; the
upper bound on accidental bills is a few dollars even if traffic
spikes.

## Cutover

Once the demo URL is live, update three places in the project:

1. README hero — replace static banner with a "Try it now" CTA linked
   to the demo.
2. The `tf-analyze.dev` homepage redirect (if a TLD is registered).
3. The Hacker News / Reddit launch posts in `docs/launch/` — they
   should reference the live URL.
