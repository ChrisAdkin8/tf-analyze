# ℹ️ MOD-STALE-001 — Registry module is significantly behind latest version

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: dry](https://img.shields.io/badge/section-dry-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Registry module is significantly behind latest version.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+"/` — _a textual regex matched somewhere in the file._
  Registry-style module source present (staleness checked via --check-registry)

## Why it likely fired

Registry-style module source present (staleness checked via --check-registry)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-STALE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Run `detect.py --check-registry` to identify modules pinned significantly behind their
latest published version on the Terraform Registry. Upgrade the `version` constraint and
run `terraform init -upgrade` to pull the newer release. Review the module's CHANGELOG
for breaking changes before upgrading across major versions.

Staleness thresholds:
- MEDIUM: pinned version is >= 1 major version behind latest
- LOW: pinned version is >= 3 minor versions behind latest (within the same major)

Findings are only emitted by `--check-registry` (requires outbound HTTPS to
registry.terraform.io). The static pass records the source pattern but does not
query the registry — keeping normal scans offline-capable.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
# Update the version constraint to the latest (check with --check-registry)
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.1"   # was ~> 3.0
}
```

## Verification

Run `terraform init -upgrade` and inspect `.terraform.lock.hcl` — the upgraded version
should match the latest from `terraform.io/registry/v1/modules/{ns}/{name}/{provider}`.
Confirm `terraform plan` shows no unintended resource replacements after the upgrade.

## References

**Source**
  - [`catalog/MOD-STALE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-STALE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-STALE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-STALE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-STALE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
