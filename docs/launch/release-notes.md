# tf-analyze v0.1.0 — first public release

> Static + plan-time Terraform security analysis with attack-graph prioritisation, MITRE ATT&CK mapping, and one-click PR fix suggestions. Drop into CI in under five minutes.

## Highlights

- **209 catalogue rules** across AWS (81), GCP (42), Azure (33), Kubernetes/Helm (5), and 48 cross-cloud rules — all with a `fix_hcl` snippet.
- **Attack-path graph** — BFS from internet-reachable resources to crown jewels (DBs, KMS keys, secrets). Findings on the critical path are promoted one urgency tier; fixes are ranked by how many crown jewels each one unblocks.
- **Adversarial scenario narratives** for HIGH/CRITICAL findings — three-to-four sentence breach stories grounded in real incidents (Capital One, Accenture, SolarWinds).
- **Inline `policy = jsonencode({...})` analysis** — six rules walking both `data "aws_iam_policy_document"` blocks AND inline JSON policies on `aws_iam_policy` / `aws_iam_role_policy`.
- **Deterministic risk score** — 0–100 with letter grade A/B/B-/C/D/F, baked into JSON / text / HTML output. Single source of truth in `scripts/detect.py:_RISK_WEIGHTS`.
- **Baseline ratcheting** (`--baseline prior.json`) for adopting on legacy repos without drowning in noise.
- **MITRE ATT&CK** mapped on 48 rules; `--format mitre` groups findings by technique.
- **VS Code extension** — real-time LSP diagnostics, attack-graph webview, inline Quick Fix, bulk remediation panel, baseline UI, MITRE view, compliance panel.
- **GitHub Action** — composite `ChrisAdkin8/tf-analyze@v0.1.0` posts inline `suggestion` blocks on every PR, uploads SARIF to Code Scanning, and exposes score / counts as workflow outputs.
- **Multi-arch Docker image** — `ghcr.io/chrisadkin8/tf-analyze:v0.1.0` (`linux/amd64` + `linux/arm64`).

## Quickstart

### As a GitHub Action

```yaml
- uses: ChrisAdkin8/tf-analyze@v0.1.0
  with:
    fail-on: HIGH
    post-pr-comment: true
```

### As a Docker container

```sh
docker run --rm -v "$(pwd):/workspace" \
  ghcr.io/chrisadkin8/tf-analyze:v0.1.0 \
  --target /workspace --format html > report.html
```

### As a VS Code extension

Install [`tfanalyze.tf-analyze`](https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze) from the Marketplace, or `code --install-extension` the `.vsix` attached to this release. The extension is self-contained — the bundled engine ships inside the VSIX.

## Test corpus

Sample reports across AWS / GCP / Azure / combined three-cloud terragoat in [`reports/`](https://github.com/ChrisAdkin8/tf-analyze/tree/main/reports). Expected output: 0 (F) — terragoat is intentionally vulnerable; the score floor is the right answer.

## What's next

- Marketplace listings (GitHub Action + VS Code Marketplace + Open VSX)
- Public web demo at [tf-analyze.dev](https://tf-analyze.dev) — live HCL editor + attack-graph visualisation
- Live "security score" and "crown jewels at risk" badges per repo

## Verification

```sh
git clone https://github.com/ChrisAdkin8/tf-analyze.git
cd tf-analyze && git checkout v0.1.0
python3 -m pytest tests/   # 411 tests, ~50s
python3 scripts/detect.py --target examples/terragoat/aws --format text | head
```

Full changelog at [CHANGELOG.md](https://github.com/ChrisAdkin8/tf-analyze/blob/v0.1.0/CHANGELOG.md).
