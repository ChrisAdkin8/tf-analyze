# ⚠️ SEC-AWS-ECS-002 — ECS task definition runs a privileged container

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **ECS task definition runs a privileged container.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/"privileged"\s*:\s*true|^\s*privileged\s*=\s*true/` — _a textual regex matched somewhere in the file._
  ECS `container_definitions` JSON contains `"privileged": true`. A
privileged container runs with all Linux capabilities and host
filesystem access, equivalent to root on the underlying EC2 host.
Compromise of the application process inside the container immediately
yields full EC2 instance control, breaking container isolation entirely.

## Why it likely fired

ECS `container_definitions` JSON contains `"privileged": true`. A
privileged container runs with all Linux capabilities and host
filesystem access, equivalent to root on the underlying EC2 host.
Compromise of the application process inside the container immediately
yields full EC2 instance control, breaking container isolation entirely.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ECS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Remove `privileged: true` from all container definitions. If a capability
is genuinely required (e.g., `NET_ADMIN` for network tools), grant it
explicitly via `linuxParameters.capabilities.add` instead:

    container_definitions = jsonencode([{
      name  = "app"
      image = "app:latest"

      linuxParameters = {
        capabilities = {
          add  = ["NET_ADMIN"]
          drop = ["ALL"]
        }
      }
    }])

Use the principle of least privilege: drop ALL capabilities and re-add
only the specific ones the process needs. Never use `privileged: true`
in production task definitions.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_ecs_task_definition" "example" {
  family = "example"
  container_definitions = jsonencode([{
    name  = "example"
    image = "example:latest"
    linuxParameters = {
      capabilities = {
        add  = []
        drop = ["ALL"]
      }
    }
  }])
}
```

## Verification

```sh
`aws ecs describe-task-definition --task-definition <family> \
  --query 'taskDefinition.containerDefinitions[*].privileged'`
must return `null` or `false` for all containers.
```

## References

**MITRE ATT&CK**
  - [`T1611`](https://attack.mitre.org/techniques/T1611/)

**Source**
  - [`catalog/SEC-AWS-ECS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ECS-002.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ECS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ECS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ECS-002
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
