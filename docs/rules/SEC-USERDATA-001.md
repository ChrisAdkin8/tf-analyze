---
title: "SEC-USERDATA-001 — user_data templates a sensitive var or contains a curl|bash pattern"
description: "tf-analyze rule SEC-USERDATA-001 (HIGH · security): user_data templates a sensitive var or contains a curl|bash pattern"
keywords: "security, high, terraform, iac, mitre-T1552.001, mitre-T1059.004, cwe-200, cwe-78"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-USERDATA-001 \u2014 user_data templates a sensitive var or contains a curl|bash pattern",
  "description": "* Secret leak \u2014 replace `user_data = <<-EOF\\n... ${var.password} ...`\n  with a `data \"aws_secretsmanager_secret_version\"` block plus an\n  IAM role on the instance, and pull the secret at runtime:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-USERDATA-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-USERDATA-001/"
  },
  "author": {
    "@type": "Organization",
    "name": "tf-analyze"
  },
  "publisher": {
    "@type": "Organization",
    "name": "tf-analyze",
    "url": "https://chrisadkin8.github.io/tf-analyze"
  },
  "keywords": "security, high, terraform, MITRE T1552.001, MITRE T1059.004, CWE-200, CWE-78",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-USERDATA-001 — user_data templates a sensitive var or contains a curl|bash pattern

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-USERDATA-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-USERDATA-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-USERDATA-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **user_data templates a sensitive var or contains a curl|bash pattern.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** on `aws_instance` matching `/\$\{var\.(password|secret|token|api_key|private_key|access_key)\b/` — _a textual regex matched somewhere in the file._
  user_data templates that interpolate `${var.<sensitive>}` either
leak the secret to anyone with `ec2:DescribeInstanceAttribute`
(the user_data is base64-stored on the instance metadata and is
readable indefinitely) or — worse — print it to cloud-init logs
on every boot. Bake secrets into Parameter Store / Secrets
Manager and pull at runtime via instance role.
2. **`grep`** on `aws_instance` matching `/curl[^\n]*\|\s*(?:bash|sh)/` — _a textual regex matched somewhere in the file._
  curl-pipe-bash inside user_data downloads + runs whatever the
URL serves at boot. No version, no checksum — see SEC-PROVISIONER-002
for the same anti-pattern on a different surface.

## Why it likely fired

user_data templates that interpolate `${var.<sensitive>}` either
leak the secret to anyone with `ec2:DescribeInstanceAttribute`
(the user_data is base64-stored on the instance metadata and is
readable indefinitely) or — worse — print it to cloud-init logs
on every boot. Bake secrets into Parameter Store / Secrets
Manager and pull at runtime via instance role.

curl-pipe-bash inside user_data downloads + runs whatever the
URL serves at boot. No version, no checksum — see SEC-PROVISIONER-002
for the same anti-pattern on a different surface.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-USERDATA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

* Secret leak — replace `user_data = <<-EOF\n... ${var.password} ...`
  with a `data "aws_secretsmanager_secret_version"` block plus an
  IAM role on the instance, and pull the secret at runtime:

      user_data = templatefile("${path.module}/init.sh.tpl", {
        secret_arn = aws_secretsmanager_secret.app.arn
      })

* curl|bash — bake the install into an AMI (Packer) and reference
  by digest. If a runtime fetch is unavoidable, verify checksums.

## Verification

Decode every instance's user_data:
    aws ec2 describe-instance-attribute --instance-id <id> \
      --attribute userData --output text --query 'UserData.Value' \
      | base64 -d
Confirm no secrets and no unverified pipes.

## References

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)
  - [`T1059.004`](https://attack.mitre.org/techniques/T1059/004/)

**CWE**
  - [`CWE-200`](https://cwe.mitre.org/data/definitions/200.html)
  - [`CWE-78`](https://cwe.mitre.org/data/definitions/78.html)

**Source**
  - [`catalog/SEC-USERDATA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-USERDATA-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-USERDATA-*` family:

- [`SEC-USERDATA-002`](./SEC-USERDATA-002.md) — user_data passes a sensitive var unencoded (base64encode missing)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-USERDATA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-USERDATA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-USERDATA-001
```

Baseline (preserves but doesn't fail CI): scan with `--baseline prior.json` after a one-time snapshot.

[← Index of all rules](../)
{% if site.giscus.enabled %}
---

## Discussion

<script src="https://giscus.app/client.js"
        data-repo="{{ site.giscus.repo }}"
        data-repo-id="{{ site.giscus.repo_id }}"
        data-category="{{ site.giscus.category }}"
        data-category-id="{{ site.giscus.category_id }}"
        data-mapping="{{ site.giscus.mapping }}"
        data-strict="0"
        data-reactions-enabled="{{ site.giscus.reactions }}"
        data-emit-metadata="{{ site.giscus.emit_metadata }}"
        data-input-position="{{ site.giscus.input_position }}"
        data-theme="{{ site.giscus.theme }}"
        data-lang="en"
        crossorigin="anonymous"
        async>
</script>

{% endif %}
