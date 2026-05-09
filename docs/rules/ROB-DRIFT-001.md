# ⚠️ ROB-DRIFT-001 — Resource uses ignore_changes = all

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Resource uses ignore_changes = all.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/(?m)^\s*ignore_changes\s*=\s*all\s*$/` — _a textual regex matched somewhere in the file._
  lifecycle block with ignore_changes = all masks all drift

## Why it likely fired

lifecycle block with ignore_changes = all masks all drift

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-DRIFT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `ignore_changes = all` with an explicit list of the specific
attributes that must be ignored. The nuclear option masks legitimate drift
and makes it impossible to detect when a resource has been modified
outside Terraform.

If the resource is truly unmanageable by Terraform, document WHY in a
comment and consider whether it should be removed from Terraform state
entirely.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_autoscaling_group" "example" {
  name = "example"
  lifecycle {
    ignore_changes = [
      desired_capacity,
      tag,
    ]
  }
}
```

## Verification

Run `terraform plan` after narrowing the ignore list. Any new diff lines
are real drift that was previously hidden.

## References

**Source**
  - [`catalog/ROB-DRIFT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-DRIFT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-DRIFT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-DRIFT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-DRIFT-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
