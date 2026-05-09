# ⚠️ MOD-PIN-001 — Module source not pinned

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

> **Module source not pinned.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"git::[^"]*"\s*$/` — _a textual regex matched somewhere in the file._
  git source without ?ref= pin
2. **`grep`** matching `/source\s*=\s*"github\.com/[^"]*"\s*$/` — _a textual regex matched somewhere in the file._
  github.com source without ?ref= pin
3. **`grep`** matching `/source\s*=\s*"bitbucket\.org/[^"]*"\s*$/` — _a textual regex matched somewhere in the file._
  bitbucket.org source without ?ref= pin
4. **`module_block_missing_arg`** (`version`) — _a `module_block_missing_arg` pattern._
  registry source without version constraint

## Why it likely fired

git source without ?ref= pin

github.com source without ?ref= pin

bitbucket.org source without ?ref= pin

registry source without version constraint

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-PIN-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pin every external module:
 - Registry: add `version = "~> X.Y"`.
 - Git: add `?ref=v1.2.3` or `?ref=<commit-sha>` to the source URL.
 - Local (`./modules/foo`): no pin needed but verify the path is stable.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
module "example" {
  source  = "hashicorp/consul/aws"
  version = "= 0.11.0"
}
```

## Verification

Run `terraform get -update` and confirm the same version resolves on
every machine. Commit `.terraform.lock.hcl`.

## References

**Source**
  - [`catalog/MOD-PIN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-PIN-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-PIN-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-PIN-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-PIN-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
