#!/usr/bin/env bash
# Upload a tf-analyze scan result to the badge service.
#
# Usage:
#   TFA_BADGE_INGEST_SECRET=... TFA_BADGE_URL=https://tf-analyze-badge.fly.dev \
#     ./upload-score.sh <owner> <repo> <branch> <path-to-detect-json>
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
: "${TFA_BADGE_INGEST_SECRET:?set TFA_BADGE_INGEST_SECRET to the shared secret}"

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

# HMAC-SHA256 over the body bytes.
signature=$(printf '%s' "$body" \
  | openssl dgst -sha256 -hmac "$TFA_BADGE_INGEST_SECRET" \
  | awk '{print $2}')

curl --fail-with-body -s -X POST "$TFA_BADGE_URL/ingest" \
  -H 'Content-Type: application/json' \
  -H "X-TFA-Signature: sha256=$signature" \
  --data-binary "$body"
echo
