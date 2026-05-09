# ⚠️ SEC-GCP-REDIS-002 — Cloud Memorystore Redis instance transit encryption disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Cloud Memorystore Redis instance transit encryption disabled.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_redis_instance` (`transit_encryption_mode`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_redis_instance` has no `transit_encryption_mode` argument.
The default is `"DISABLED"` — all Redis client-to-server traffic is
unencrypted within the VPC. A compromised node, VPC route, or
misconfigured peering can capture every command and response,
including AUTH credentials.
2. **`resource_arg`** on `google_redis_instance` (`transit_encryption_mode`) matching `/DISABLED/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `google_redis_instance` explicitly sets
`transit_encryption_mode = "DISABLED"`. All Redis traffic is
cleartext within the VPC.

## Why it likely fired

`google_redis_instance` has no `transit_encryption_mode` argument.
The default is `"DISABLED"` — all Redis client-to-server traffic is
unencrypted within the VPC. A compromised node, VPC route, or
misconfigured peering can capture every command and response,
including AUTH credentials.

`google_redis_instance` explicitly sets
`transit_encryption_mode = "DISABLED"`. All Redis traffic is
cleartext within the VPC.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-REDIS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable TLS for in-transit encryption:

    resource "google_redis_instance" "cache" {
      name                    = "cache"
      memory_size_gb          = 1
      transit_encryption_mode = "SERVER_AUTHENTICATION"
      auth_enabled            = true
    }

`SERVER_AUTHENTICATION` requires clients to trust the server TLS
certificate (CA bundle available via the instance `server_ca_certs`
output). `CLIENT_AUTHENTICATION` additionally requires a client cert.
Update all consumer connection strings to use `rediss://` (TLS) before
enabling to avoid connection failures.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_redis_instance" "example" {
  # ... other arguments ...
  transit_encryption_mode = "SERVER_AUTHENTICATION"
}
```

## Verification

```sh
`gcloud redis instances describe <name> --region=<region> \
  --format='value(transitEncryptionMode)'`
must return `SERVER_AUTHENTICATION`.
```

## References

**Source**
  - [`catalog/SEC-GCP-REDIS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-REDIS-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-REDIS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-REDIS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-REDIS-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
