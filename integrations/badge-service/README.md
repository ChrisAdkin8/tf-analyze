# Badge service — DEPRECATED in R30.15

> **The standalone badge service was never deployed and is no longer the
> recommended path.** Badge rendering is now part of the public scanner at
> [`tfanalyze.com/badge/<owner>/<repo>.svg`](https://tfanalyze.com/badge/ChrisAdkin8/tf-analyze.svg).

## What changed

The badge service in this directory was designed around an HMAC-signed
`POST /ingest` flow: CI would run `detect.py --format json`, then
upload the score to a separate Fly app (`tf-analyze-badge.fly.dev`).
That separate Fly app was never created.

When `tfanalyze.com` shipped (R30.14, the public scanner permalink),
the per-SHA cache it builds — keyed at
`/var/cache/tf-analyze/<owner>_<repo>_<sha>.json` on the Fly volume —
became a natural source for badge rendering. The unified route now
reads from that cache and renders the same shields.io-shape SVG.

| Old (this dir) | New (R30.15) |
|---|---|
| `https://tf-analyze-badge.fly.dev/score/<owner>/<repo>.svg` | `https://tfanalyze.com/badge/<owner>/<repo>.svg` |
| In-memory store, fed by HMAC-signed `POST /ingest` from CI | Reads the public scanner's per-SHA volume cache |
| Two Fly apps to deploy | One Fly app, same image |
| Score depends on CI pushing after every scan | Score updates the next time someone visits `/scan/<owner>/<repo>` |

## Why it stays in the tree (for now)

- **Reference value.** The SVG rendering code was lifted into
  [`demo/_badge.py`](../../demo/_badge.py); the rest of `server.py`
  (HMAC verification, the request shape, validation regexes) is useful
  as a pattern if a private-repo / push-from-CI use case ever materialises.
- **No clean deletion in the same commit as the unified shipping path.**
  A follow-up commit will git-rm `Dockerfile`, `fly.toml`, `server.py`,
  `requirements.txt`, and `scripts/upload-score.sh` once the new path
  has been stable in production for a couple of weeks.

## If you actually need push-from-CI badges

You don't, in 99% of cases — the unified `/badge/` route on
`tfanalyze.com` covers public repos out of the box. The remaining 1%
(private repos that can't be scanned by the public service, or
on-premises forks of this engine) can lift the HMAC code from
`server.py` and graft it onto a private deployment of `demo/app.py`.
That's the supported path going forward.
