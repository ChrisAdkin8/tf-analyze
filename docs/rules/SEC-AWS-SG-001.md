# ⚠️ SEC-AWS-SG-001 — Security group allows ingress from 0.0.0.0/0

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

> **Security group allows ingress from 0.0.0.0/0.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]/` — _a textual regex matched somewhere in the file._
  security group ingress rule open to all IPv4
2. **`grep`** matching `/ipv6_cidr_blocks\s*=\s*\["::/0"\]/` — _a textual regex matched somewhere in the file._
  security group ingress rule open to all IPv6

## Why it likely fired

security group ingress rule open to all IPv4

security group ingress rule open to all IPv6

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-SG-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict `cidr_blocks` to the specific IP ranges that need access.
For SSH/RDP, use a bastion host or AWS Systems Manager Session Manager
instead of opening ports to the internet. For web traffic, place an
ALB/NLB in front with a restrictive security group.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
# Replace 0.0.0.0/0 with a specific CIDR range:
ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
}
```

_Restricting CIDR blocks updates the security group in-place; existing connections are not interrupted but new connections are blocked._

## Verification

Run `aws ec2 describe-security-groups --group-ids <sg-id>` and confirm
no ingress rules have `0.0.0.0/0` or `::/0` as source.

## References

**CIS Benchmark**
  - `CIS 5.2`
  - `CIS 5.3`

**PCI-DSS**
  - `Req-1.2`

**Source**
  - [`catalog/SEC-AWS-SG-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-SG-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-SG-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-SG-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-SG-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
