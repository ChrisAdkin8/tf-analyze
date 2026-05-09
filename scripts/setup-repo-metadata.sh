#!/usr/bin/env bash
# Set the GitHub repo description, homepage, and topics so search and
# Marketplace surfaces have something to render. Run once after the
# first push of action.yml + a v* tag.
#
# Requires `gh` (GitHub CLI) authenticated as the repo owner.
#
# Usage:
#   ./scripts/setup-repo-metadata.sh ChrisAdkin8/tf-analyze
set -euo pipefail

REPO="${1:-ChrisAdkin8/tf-analyze}"

DESCRIPTION="Static + plan-time Terraform security analysis with attack-graph prioritisation, MITRE ATT&CK mapping, and one-click PR fix suggestions. 209 rules, 100% fix_hcl coverage."
HOMEPAGE="https://github.com/${REPO}"

TOPICS=(
  terraform
  terraform-security
  security
  static-analysis
  iac
  iac-security
  hashicorp
  attack-graph
  mitre-attack
  cis-benchmark
  pci-dss
  soc2
  oscal
  sarif
  pre-commit
  vscode-extension
  github-action
  hcl
  cloud-security
  devsecops
)

echo "→ Setting description + homepage on ${REPO}"
gh repo edit "${REPO}" \
  --description "${DESCRIPTION}" \
  --homepage "${HOMEPAGE}"

echo "→ Replacing topics"
gh api -X PUT "repos/${REPO}/topics" \
  -F "names[]=$(IFS=,; echo "${TOPICS[*]}" | sed 's/,/\&names[]=/g')" \
  --jq '.names | length' >/dev/null

# The above gh api invocation can be brittle; fall back to the high-level
# wrapper that handles the array correctly.
gh repo edit "${REPO}" $(printf -- "--add-topic %s " "${TOPICS[@]}")

echo
echo "✓ Repo metadata applied. Verify at https://github.com/${REPO}"
echo "  Topics show under the repo name; description sits next to the title."
