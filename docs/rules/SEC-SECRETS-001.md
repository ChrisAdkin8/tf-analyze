---
title: "SEC-SECRETS-001 — Hardcoded credential or API key in Terraform source"
description: "tf-analyze rule SEC-SECRETS-001 (CRITICAL · security): Hardcoded credential or API key in Terraform source"
keywords: "security, critical, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-SECRETS-001 \u2014 Hardcoded credential or API key in Terraform source",
  "description": "Replace every hardcoded credential with a reference to a secrets\nmanager:\n- GCP: `data.google_secret_manager_secret_version.creds.secret_data`\n- AWS: `data.aws_secretsmanager_secret_version.creds.secret_string`\n- Azure: `data.azurerm_key_va",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SECRETS-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SECRETS-001/"
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
  "keywords": "security, critical, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-SECRETS-001 — Hardcoded credential or API key in Terraform source

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-SECRETS-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-SECRETS-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-SECRETS-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Hardcoded credential or API key in Terraform source.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/(?:password|secret|api_key|master_password|admin_password)\s*=\s*"[^$"{][^"]{7,}"/` — _a textual regex matched somewhere in the file._
  Literal string assigned to a password/secret/key argument that
is not a variable reference (`var.*`), a data reference, or a
local function call. Matches patterns like
`password = "s3cr3t123"` that embed the credential directly.
hcl_context strips comments first so examples in `# …` lines
do not produce false positives.
2. **`grep`** matching `/AKIA[0-9A-Z]{16}/` — _a textual regex matched somewhere in the file._
  AWS IAM access key ID literal in source.
3. **`grep`** matching `/sk-(?:live|test|proj)-[A-Za-z0-9]+/` — _a textual regex matched somewhere in the file._
  Stripe / OpenAI / similar API key prefix in source.
4. **`grep`** matching `/(?:password|secret|api_key)\s*=\s*"[^$"{][^"]{7,}"/` — _a textual regex matched somewhere in the file._
  Same pattern in .tfvars and .auto.tfvars files. tfvars are often
committed to repos despite containing credentials — and are
frequently NOT gitignored. The fixed file_glob matching (lstrip "*/")
means this also catches *.auto.tfvars files.
5. **`grep`** matching `/"(?:password|secret|api_key)"\s*:\s*"[^$"{][^"]{7,}"/` — _a textual regex matched somewhere in the file._
  Same pattern in JSON-format tfvars (*.tfvars.json). These are
auto-loaded by Terraform and equally capable of containing secrets.

## Why it likely fired

Literal string assigned to a password/secret/key argument that
is not a variable reference (`var.*`), a data reference, or a
local function call. Matches patterns like
`password = "s3cr3t123"` that embed the credential directly.
hcl_context strips comments first so examples in `# …` lines
do not produce false positives.

AWS IAM access key ID literal in source.

Stripe / OpenAI / similar API key prefix in source.

Same pattern in .tfvars and .auto.tfvars files. tfvars are often
committed to repos despite containing credentials — and are
frequently NOT gitignored. The fixed file_glob matching (lstrip "*/")
means this also catches *.auto.tfvars files.

Same pattern in JSON-format tfvars (*.tfvars.json). These are
auto-loaded by Terraform and equally capable of containing secrets.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SECRETS-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace every hardcoded credential with a reference to a secrets
manager:
- GCP: `data.google_secret_manager_secret_version.creds.secret_data`
- AWS: `data.aws_secretsmanager_secret_version.creds.secret_string`
- Azure: `data.azurerm_key_vault_secret.creds.value`
- HashiCorp Vault: `data.vault_generic_secret.creds.data["password"]`

For passwords on managed databases, prefer `random_password` resource
with the result stored in the secrets manager — avoids checked-in
values entirely.

If the credential is already committed, rotate it immediately — git
history retains it even after the line is removed. Use `git filter-repo`
or BFG Repo Cleaner to purge the history.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Replace hardcoded credential with a variable (never set a default)
variable "db_password" {
  type      = string
  sensitive = true
}

# Or fetch from AWS Secrets Manager
data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/app/db_password"
}

resource "aws_db_instance" "app" {
  password = var.db_password
  # or: password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]
}
```

## Verification

Re-run tf-analyze. SEC-SECRETS-001 should not fire. Confirm the
credential is retrieved at plan time from the secrets manager and
does not appear in `terraform show` output (it will be marked
`(sensitive value)` if the attribute is marked sensitive).

## References

**PCI-DSS**
  - `Req-3.5`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**Source**
  - [`catalog/SEC-SECRETS-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SECRETS-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SECRETS-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SECRETS-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SECRETS-001
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
