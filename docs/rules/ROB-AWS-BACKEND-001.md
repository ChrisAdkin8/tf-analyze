# ⚠️ ROB-AWS-BACKEND-001 — Terraform S3 backend missing DynamoDB state locking

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

> **Terraform S3 backend missing DynamoDB state locking.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`backend_missing_arg`** (`dynamodb_table`) — _a `backend_missing_arg` pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-AWS-BACKEND-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `dynamodb_table` to the S3 backend configuration:

    terraform {
      backend "s3" {
        bucket         = "my-terraform-state"
        key            = "terraform.tfstate"
        region         = "us-east-1"
        dynamodb_table = "terraform-state-lock"
        encrypt        = true
      }
    }

Without state locking, concurrent `terraform apply` runs on the same
workspace will race and can corrupt the state file. The DynamoDB table
needs a `LockID` string hash key; `terraform init` does not create it
automatically.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
terraform {
  backend "s3" {
    bucket         = "my-tf-state"
    key            = "env/prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    kms_key_id     = "alias/terraform-state"
  }
}
```

## Verification

Run two simultaneous `terraform plan` invocations and confirm the
second is blocked with "Error acquiring the state lock". Or check the
DynamoDB table in the AWS console for an active lock entry.

## References

**Source**
  - [`catalog/ROB-AWS-BACKEND-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-AWS-BACKEND-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-AWS-BACKEND-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-AWS-BACKEND-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-AWS-BACKEND-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
