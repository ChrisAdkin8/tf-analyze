#!/usr/bin/env bash
# Print the badge upload key for one repository.
#
# Usage (operator, with the service's master secret in the environment):
#   TFA_BADGE_INGEST_SECRET=... ./derive-key.sh <owner> <repo>
#
# Give the printed key to that repository's CI as TFA_BADGE_INGEST_KEY
# (for upload-score.sh). It can write only <owner>/<repo>'s badge; the
# master secret never leaves the operator. Mirrors
# server.repo_ingest_key().
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <owner> <repo>" >&2
  exit 2
fi
: "${TFA_BADGE_INGEST_SECRET:?set TFA_BADGE_INGEST_SECRET to the service master secret}"

TFA_REPO_ID="$1/$2" python3 -c '
import hashlib, hmac, os
key = os.environ["TFA_BADGE_INGEST_SECRET"].encode()
print(hmac.new(key, ("ingest:" + os.environ["TFA_REPO_ID"]).encode(), hashlib.sha256).hexdigest())'
