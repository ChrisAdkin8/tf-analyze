# ⚠️ SEC-AWS-ELASTICACHE-001 — ElastiCache replication group missing encryption

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **ElastiCache replication group missing encryption.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_elasticache_replication_group` (`at_rest_encryption_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
2. **`hcl_attr`** on `aws_elasticache_replication_group` (`at_rest_encryption_enabled`) not equal to `True` — _an attribute value differs from the expected literal._
3. **`resource_missing_arg`** on `aws_elasticache_replication_group` (`transit_encryption_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
4. **`hcl_attr`** on `aws_elasticache_replication_group` (`transit_encryption_enabled`) not equal to `True` — _an attribute value differs from the expected literal._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ELASTICACHE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable both at-rest and in-transit encryption:

    resource "aws_elasticache_replication_group" "app" {
      replication_group_id = "app"
      description          = "App cache"

      at_rest_encryption_enabled = true
      transit_encryption_enabled = true
      auth_token                 = var.redis_auth_token
    }

In-transit encryption (TLS) requires `auth_token` to be set as well.
Without both flags, cache traffic and data are visible to anyone with
network access to the cluster endpoint.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "aws_elasticache_replication_group" "example" {
  # ... other arguments ...
  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  auth_token                  = var.auth_token
}
```

_Encryption settings cannot be changed on an existing ElastiCache cluster — requires replacement._

## Verification

```sh
`aws elasticache describe-replication-groups --replication-group-id <id> \
  --query 'ReplicationGroups[0].{AtRest:AtRestEncryptionEnabled,InTransit:TransitEncryptionEnabled}'`
both values must be `true`.
```

## References

**Source**
  - [`catalog/SEC-AWS-ELASTICACHE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ELASTICACHE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ELASTICACHE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ELASTICACHE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ELASTICACHE-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
