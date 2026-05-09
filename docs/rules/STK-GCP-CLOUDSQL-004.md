# ⚠️ STK-GCP-CLOUDSQL-004 — Cloud SQL instance does not require SSL connections

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Cloud SQL instance does not require SSL connections.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. _Conditional: only applies when `google ≥ 4.0`._

## What this checks

1. **`resource_missing_arg`** on `google_sql_database_instance` (`settings.ip_configuration.require_ssl`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`hcl_attr`** on `google_sql_database_instance` (`settings.ip_configuration.require_ssl`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `require_ssl = true` in the `ip_configuration` block:

    settings {
      ip_configuration {
        require_ssl     = true
        ipv4_enabled    = false
        private_network = google_compute_network.vpc.id
      }
    }

Without this flag, clients can connect over unencrypted TCP. Any
network path between client and Cloud SQL (VPC, Cloud Interconnect,
Cloud VPN) becomes a potential eavesdropping or MITM point.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  # ... other arguments ...
  settings {
    ip_configuration {
      ssl_mode = "ENCRYPTED_ONLY"
    }
  }
}
```

## Verification

```sh
`gcloud sql instances describe <name> \
  --format='value(settings.ipConfiguration.requireSsl)'`
must return `True`.
```

## References

**CIS Benchmark**
  - `CIS 6.1.2`

**Source**
  - [`catalog/STK-GCP-CLOUDSQL-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDSQL-004.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDSQL-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDSQL-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDSQL-004
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
