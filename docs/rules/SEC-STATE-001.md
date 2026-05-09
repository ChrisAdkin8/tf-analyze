# 🚨 SEC-STATE-001 — .tfstate file committed to the repository

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **.tfstate file committed to the repository.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`tfstate_in_repo`** — _a `*.tfstate` file is committed to the repository._
  .tfstate, .tfstate.backup, or .tfstate~ file present in the scanned tree

## Why it likely fired

.tfstate, .tfstate.backup, or .tfstate~ file present in the scanned tree

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-STATE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

`.tfstate` contains plaintext attributes of every resource — including
provider secrets that were resolved at apply time (database passwords,
service-account keys, bucket ACLs). A committed state file is a leaked
credentials file.

1. Rotate every credential that appears in the committed state (service
   accounts, database users, any `sensitive` output value).
2. Add `*.tfstate`, `*.tfstate.*`, and `.terraform/` to `.gitignore`.
3. Purge from history: `git filter-repo --path-glob '*.tfstate*' --invert-paths`.
4. Move to a remote backend (`backend "gcs" {}` or `backend "s3" {}`)
   with encryption-at-rest and versioning enabled.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# 1. Add to .gitignore
# *.tfstate
# *.tfstate.*
# .terraform/

# 2. Move to a remote backend
terraform {
  backend "s3" {
    bucket         = "myorg-terraform-state"
    key            = "envs/prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}
```

## Verification

```sh
`find . -name '*.tfstate*' -not -path './.terraform/*'` returns empty,
and `git log --all --full-history -- '*.tfstate*'` returns empty.
```

## References

**CIS Benchmark**
  - `CIS 1.1`

**PCI-DSS**
  - `Req-3.5`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**Source**
  - [`catalog/SEC-STATE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-STATE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-STATE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-STATE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-STATE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
