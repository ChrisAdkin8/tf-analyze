# ⚠️ SEC-PROVISIONER-001 — Provisioner block used for shell execution

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

> **Provisioner block used for shell execution.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/provisioner\s+"local-exec"/` — _a textual regex matched somewhere in the file._
  local-exec provisioner runs arbitrary shell commands
2. **`grep`** matching `/provisioner\s+"remote-exec"/` — _a textual regex matched somewhere in the file._
  remote-exec provisioner runs commands on remote hosts

## Why it likely fired

local-exec provisioner runs arbitrary shell commands

remote-exec provisioner runs commands on remote hosts

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-PROVISIONER-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Provisioners are a last resort. Replace with provider-native resources
where possible:
- `local-exec` for scripts → `terraform_data` with `provisioner` only
  when no provider resource exists, or use `null_resource` with explicit
  `triggers` to control re-execution.
- `remote-exec` → cloud-init (`user_data`), Packer images, or
  configuration management (Ansible, Chef, Puppet).
If a provisioner is genuinely needed, document the justification with
an inline `# tf-analyze:ignore SEC-PROVISIONER-001` comment.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Replace remote-exec with user_data / cloud-init
resource "aws_instance" "app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  user_data = templatefile("${path.module}/cloud-init.sh.tpl", {
    environment = var.environment
  })
}

# Replace local-exec trigger with terraform_data
resource "terraform_data" "init" {
  triggers_replace = [aws_instance.app.id]
  provisioner "local-exec" {
    command = "echo 'only use as last resort — document why'"
  }
}
```

## Verification

Search for `provisioner` blocks in the codebase. Confirm each remaining
provisioner is documented with a justification comment or suppression.

## References

**MITRE ATT&CK**
  - [`T1059`](https://attack.mitre.org/techniques/T1059/)

**Source**
  - [`catalog/SEC-PROVISIONER-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-PROVISIONER-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-PROVISIONER-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-PROVISIONER-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-PROVISIONER-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](./)
