# ⚠️ STK-GCP-DNS-001 — Cloud DNS managed zone missing DNSSEC

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Cloud DNS managed zone missing DNSSEC.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_dns_managed_zone` (`dnssec_config.state`) — _the resource is missing a required attribute (or nested attribute path)._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-DNS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `dnssec_config { state = "on" }`:

    resource "google_dns_managed_zone" "prod" {
      name     = "prod-zone"
      dns_name = "example.com."

      dnssec_config {
        state = "on"
      }
    }

DNSSEC protects against cache-poisoning attacks that redirect resolvers
to attacker-controlled endpoints. Required by CIS GCP 3.9.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_dns_managed_zone" "example" {
  name     = "example"
  dns_name = "example.com."
  dnssec_config {
    state = "on"
  }
}
```

## Verification

```sh
`gcloud dns managed-zones describe <name> --format='value(dnssecConfig.state)'`
must return `on`.
```

## References

**CIS Benchmark**
  - `CIS 3.9`

**Source**
  - [`catalog/STK-GCP-DNS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-DNS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-DNS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-DNS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-DNS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
