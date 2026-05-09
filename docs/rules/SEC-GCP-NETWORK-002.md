# 🚨 SEC-GCP-NETWORK-002 — RDP (tcp:3389) exposed to 0.0.0.0/0

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **RDP (tcp:3389) exposed to 0.0.0.0/0.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`firewall_open_port`** — _a `google_compute_firewall` allows the named port from `0.0.0.0/0`._
  `google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]`
and an `allow {}` block containing port 3389. World-open RDP is
exploited by ransomware operators within minutes of exposure.

## Why it likely fired

`google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]`
and an `allow {}` block containing port 3389. World-open RDP is
exploited by ransomware operators within minutes of exposure.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-NETWORK-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict `source_ranges` to corporate CIDRs or use IAP TCP forwarding
for RDP access. Never expose tcp:3389 to the public internet.

    resource "google_compute_firewall" "iap_rdp" {
      name    = "iap-rdp"
      network = google_compute_network.vpc.id

      source_ranges = ["35.235.240.0/20"]

      allow {
        protocol = "tcp"
        ports    = ["3389"]
      }

      target_tags = ["iap-rdp"]
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_firewall" "iap_rdp" {
  name          = "iap-rdp"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  target_tags = ["iap-rdp"]
}
```

## Verification

```sh
`gcloud compute firewall-rules list --filter='allowed.ports:3389 AND sourceRanges:0.0.0.0/0'`
should return zero rows.
```

## References

**CIS Benchmark**
  - `CIS 3.7`

**Related rules**
  - [`SEC-GCP-NETWORK-001`](./SEC-GCP-NETWORK-001.md)

**Source**
  - [`catalog/SEC-GCP-NETWORK-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-NETWORK-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-NETWORK-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-NETWORK-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-NETWORK-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
