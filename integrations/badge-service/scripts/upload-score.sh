#!/usr/bin/env bash
# Upload a tf-analyze scan result to the badge service.
#
# Usage:
#   TFA_BADGE_INGEST_KEY=... TFA_BADGE_URL=https://tf-analyze-badge.fly.dev \
#     ./upload-score.sh <owner> <repo> <branch> <path-to-detect-json>
#
# TFA_BADGE_INGEST_KEY is this repository's own upload key, not the
# service's master secret: the operator derives it with
# `scripts/derive-key.sh <owner> <repo>`. It can write only this repo's badge.
#
# Designed to be wired into a GitHub Actions step or post-merge hook.
# Drives the public README badge whose URL is:
#   https://<TFA_BADGE_URL>/score/<owner>/<repo>.svg
#   https://<TFA_BADGE_URL>/score/<owner>/<repo>/<branch>.svg
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <owner> <repo> <branch> <detect-json>" >&2
  exit 2
fi

owner="$1"
repo="$2"
branch="$3"
detect_json="$4"

: "${TFA_BADGE_URL:?set TFA_BADGE_URL to the badge-service base URL}"
: "${TFA_BADGE_INGEST_KEY:?set TFA_BADGE_INGEST_KEY to the upload key for this repo (scripts/derive-key.sh)}"

if [ ! -f "$detect_json" ]; then
  echo "no such file: $detect_json" >&2
  exit 1
fi

# Build the request body. The body MUST be byte-identical to what we
# sign — `jq -c` produces a stable serialisation regardless of key
# order in the source file.
body=$(jq -c \
  --arg owner "$owner" \
  --arg repo "$repo" \
  --arg branch "$branch" \
  --slurpfile scan "$detect_json" \
  '{owner: $owner, repo: $repo, branch: $branch, scan: $scan[0]}')

# HMAC-SHA256 over "<timestamp>.<body>"; the server refuses a stale or
# replayed timestamp. Computed in Python with the key read from the
# environment: `openssl -hmac <key>` put it in the process list, where any
# local user could read it.
timestamp=$(date +%s)
signature=$(printf '%s' "$body" | TFA_TS="$timestamp" python3 -c '
import hashlib, hmac, os, sys
key = os.environ["TFA_BADGE_INGEST_KEY"].encode()
msg = os.environ["TFA_TS"].encode() + b"." + sys.stdin.buffer.read()
print(hmac.new(key, msg, hashlib.sha256).hexdigest())')

curl --fail-with-body -s -X POST "$TFA_BADGE_URL/ingest" \
  -H 'Content-Type: application/json' \
  -H "X-TFA-Timestamp: $timestamp" \
  -H "X-TFA-Signature: sha256=$signature" \
  --data-binary "$body"
echo
