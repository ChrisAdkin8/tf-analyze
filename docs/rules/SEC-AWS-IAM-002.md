# 🚨 SEC-AWS-IAM-002 — IAM assume role policy with wildcard Principal

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **IAM assume role policy with wildcard Principal.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/"Principal"\s*:\s*"\*"/` — _a textual regex matched somewhere in the file._
  IAM assume role policy with Principal = "*"
2. **`grep`** matching `/principals\s*\{[^}]*type\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
  aws_iam_role inline principals block with type = "*"
3. **`grep`** matching `/Principal\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
  IAM assume role policy Principal = "*" in jsonencode HCL object syntax

## Why it likely fired

IAM assume role policy with Principal = "*"

aws_iam_role inline principals block with type = "*"

IAM assume role policy Principal = "*" in jsonencode HCL object syntax

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict the `Principal` in assume role policies to specific AWS account
IDs, IAM roles, or services. A wildcard principal (`"Principal": "*"`)
allows any entity in the world to call `sts:AssumeRole`, effectively
making the role public unless a restrictive Condition is also present.
Replace `"Principal": "*"` with the exact ARN(s) of the trusted entity,
e.g. `"Principal": {"Service": "lambda.amazonaws.com"}` or
`"Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"}`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_iam_role" "example" {
  name = "example"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
```

## Verification

Run `aws iam get-role --role-name <name>` and inspect the
`AssumeRolePolicyDocument`. Confirm there is no `"Principal": "*"`
without a restrictive `Condition` block. Run `terraform plan` and
verify the rendered policy document in the plan output has no
wildcard principal.

## References

**CIS Benchmark**
  - `CIS 1.16`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**Source**
  - [`catalog/SEC-AWS-IAM-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
