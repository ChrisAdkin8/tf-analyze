# 🚨 SEC-GCP-NETWORK-001 — SSH (tcp:22) exposed to 0.0.0.0/0

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **SSH (tcp:22) exposed to 0.0.0.0/0.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`firewall_open_port`** — _a `google_compute_firewall` allows the named port from `0.0.0.0/0`._
  `google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]`
and an `allow {}` block containing port 22 (or a range that
includes it). World-open SSH is the most-attacked attack
surface on GCP — credential stuffing and zero-day exploits
against unpatched sshd find it within minutes.

## Why it likely fired

`google_compute_firewall` with `source_ranges = ["0.0.0.0/0"]`
and an `allow {}` block containing port 22 (or a range that
includes it). World-open SSH is the most-attacked attack
surface on GCP — credential stuffing and zero-day exploits
against unpatched sshd find it within minutes.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-NETWORK-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace public SSH ingress with **Identity-Aware Proxy** TCP
forwarding. The trio is:

    resource "google_compute_firewall" "iap_ssh" {
      name      = "iap-ssh"
      network   = google_compute_network.vpc.id
      direction = "INGRESS"

      # IAP CIDR — fixed Google-owned range
      source_ranges = ["35.235.240.0/20"]

      allow {
        protocol = "tcp"
        ports    = ["22"]
      }

      target_tags = ["iap-ssh"]
    }

Then `gcloud compute ssh <vm> --tunnel-through-iap` from any
network. If IAP isn't an option, restrict `source_ranges` to
corporate egress CIDRs and rotate them out of band.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_compute_firewall" "iap_ssh" {
  name          = "iap-ssh"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  target_tags = ["iap-ssh"]
}
```

## Verification

After applying:

    gcloud compute firewall-rules list \\
      --filter='allowed.ports:22 AND sourceRanges:0.0.0.0/0' \\
      --format='value(name)'

Should return zero rows. Re-run tf-analyze to confirm clean.

## References

**CIS Benchmark**
  - `CIS 3.6`

**PCI-DSS**
  - `Req-1.2`

**Related rules**
  - [`SEC-NETWORK-002`](./SEC-NETWORK-002.md)

**Source**
  - [`catalog/SEC-GCP-NETWORK-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-NETWORK-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-NETWORK-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-NETWORK-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-NETWORK-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
