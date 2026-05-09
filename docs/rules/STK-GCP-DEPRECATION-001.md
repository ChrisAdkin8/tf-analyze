# 💡 STK-GCP-DEPRECATION-001 — Resource uses deprecated argument

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Resource uses deprecated argument.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_container_cluster` (`enable_legacy_abac`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  enable_legacy_abac is deprecated; remove it (ABAC disabled by default)
2. **`resource_arg`** on `google_container_cluster` (`logging_service`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  logging_service is deprecated; use logging_config block instead
3. **`resource_arg`** on `google_container_cluster` (`monitoring_service`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  monitoring_service is deprecated; use monitoring_config block instead
4. **`resource_arg`** on `google_compute_instance` (`metadata_startup_script`) matching `/.*/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  metadata_startup_script is deprecated; use metadata.startup-script instead
5. **`grep`** matching `/resource\s+"google_compute_address".*\n.*\baddress\b/` — _a textual regex matched somewhere in the file._
  google_compute_address.address argument renamed in v6

## Why it likely fired

enable_legacy_abac is deprecated; remove it (ABAC disabled by default)

logging_service is deprecated; use logging_config block instead

monitoring_service is deprecated; use monitoring_config block instead

metadata_startup_script is deprecated; use metadata.startup-script instead

google_compute_address.address argument renamed in v6

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-DEPRECATION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace deprecated arguments with their successors before the next major
provider version removes them. Check the Google provider changelog for
migration guidance.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_container_cluster" "app" {
  # Remove deprecated enable_legacy_abac — ABAC is disabled by default
  # Remove deprecated logging_service / monitoring_service — use blocks instead
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }
  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }
}

resource "google_compute_instance" "app" {
  metadata = {
    "startup-script" = file("${path.module}/startup.sh")
  }
  # Remove deprecated metadata_startup_script argument
}
```

## Verification

Run `terraform validate` and `terraform plan` — no deprecation warnings
should appear.

## References

**Source**
  - [`catalog/STK-GCP-DEPRECATION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-DEPRECATION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-DEPRECATION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-DEPRECATION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-DEPRECATION-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
