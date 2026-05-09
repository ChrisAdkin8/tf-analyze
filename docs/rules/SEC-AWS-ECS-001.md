# ⚠️ SEC-AWS-ECS-001 — ECS task definition exposes secrets in plaintext environment variables

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **ECS task definition exposes secrets in plaintext environment variables.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/(?i)(?:"name"|name)\s*[=:]\s*"[^"]*(?:password|secret_key|secret|api_key|token|credential|private_key)[^"]*"[^\n}]{0,80}\n[^\n}]{0,80}(?:"value"|value)\s*[=:]\s*"[^\$"\{][^"]*"/` — _a textual regex matched somewhere in the file._
  ECS `container_definitions` JSON contains an environment variable whose
name looks like a secret (PASSWORD, SECRET, TOKEN, API_KEY, CREDENTIAL)
with a hardcoded `value`. Secrets passed as plaintext environment
variables are visible in the ECS console, AWS CloudTrail describe-task
events, and any container process that reads its own environment.
Use `secrets` (backed by Secrets Manager or SSM Parameter Store) instead.

## Why it likely fired

ECS `container_definitions` JSON contains an environment variable whose
name looks like a secret (PASSWORD, SECRET, TOKEN, API_KEY, CREDENTIAL)
with a hardcoded `value`. Secrets passed as plaintext environment
variables are visible in the ECS console, AWS CloudTrail describe-task
events, and any container process that reads its own environment.
Use `secrets` (backed by Secrets Manager or SSM Parameter Store) instead.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ECS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace plaintext `environment` entries with `secrets` references:

    resource "aws_ecs_task_definition" "app" {
      family = "app"

      container_definitions = jsonencode([{
        name  = "app"
        image = "app:latest"

        # BAD — plaintext secret:
        # environment = [{ name = "DB_PASSWORD", value = "s3cr3t" }]

        # GOOD — Secrets Manager reference:
        secrets = [
          {
            name      = "DB_PASSWORD"
            valueFrom = aws_secretsmanager_secret.db_password.arn
          }
        ]
      }])
    }

ECS injects Secrets Manager / SSM values at container start time.
The plaintext value never appears in task metadata or CloudTrail.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_ecs_task_definition" "example" {
  family = "example"
  container_definitions = jsonencode([{
    name  = "example"
    image = "example:latest"
    secrets = [
      {
        name      = "DB_PASSWORD"
        valueFrom = aws_secretsmanager_secret.example.arn
      }
    ]
  }])
}
```

## Verification

```sh
`aws ecs describe-task-definition --task-definition <family> \
  --query 'taskDefinition.containerDefinitions[*].environment'`
must return an empty list or contain only non-sensitive values.
Secrets should appear under `secrets`, not `environment`.
```

## References

**PCI-DSS**
  - `Req-3.5`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**Source**
  - [`catalog/SEC-AWS-ECS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ECS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ECS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ECS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ECS-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
