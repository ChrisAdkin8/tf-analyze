---
title: "SEC-EPHEMERAL-001 — Vault secret data source should use ephemeral on Terraform 1.10+"
description: "tf-analyze rule SEC-EPHEMERAL-001 (MEDIUM · security): Vault secret data source should use ephemeral on Terraform 1.10+"
keywords: "security, medium, terraform, iac"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-EPHEMERAL-001 \u2014 Vault secret data source should use ephemeral on Terraform 1.10+",
  "description": "If `required_version` permits Terraform 1.10 or later, replace:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-EPHEMERAL-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-EPHEMERAL-001/"
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
  "keywords": "security, medium, terraform",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-EPHEMERAL-001 — Vault secret data source should use ephemeral on Terraform 1.10+

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-EPHEMERAL-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-EPHEMERAL-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-EPHEMERAL-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Vault secret data source should use ephemeral on Terraform 1.10+.** This rule has `default_urgency: MEDIUM` and operates on a module blast radius. _Conditional: only applies when `terraform ≥ 1.10`._

## What this checks

1. **`data_source_present`** — _a `data_source_present` pattern._
  `data "vault_kv_secret_v2"` persists the secret value into Terraform
state. On Terraform 1.10+ the `ephemeral` block reads the secret
without committing it to state, eliminating an entire class of state
exposure (state file in object storage, state drift via
`terraform show`, accidental git commit of plan output).

## Why it likely fired

`data "vault_kv_secret_v2"` persists the secret value into Terraform
state. On Terraform 1.10+ the `ephemeral` block reads the secret
without committing it to state, eliminating an entire class of state
exposure (state file in object storage, state drift via
`terraform show`, accidental git commit of plan output).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-EPHEMERAL-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

If `required_version` permits Terraform 1.10 or later, replace:

    data "vault_kv_secret_v2" "creds" {
      mount = "secret"
      name  = "app/db"
    }

    resource "google_sql_user" "app" {
      password = data.vault_kv_secret_v2.creds.data["password"]
      ...
    }

with:

    ephemeral "vault_kv_secret_v2" "creds" {
      mount = "secret"
      name  = "app/db"
    }

    resource "google_sql_user" "app" {
      password = ephemeral.vault_kv_secret_v2.creds.data["password"]
      ...
    }

The ephemeral value is available during plan/apply but never written
to state. Combine with `write_only` arguments where supported (see
the Vault and SQL provider docs) so the value also doesn't appear in
the apply diff.

If you cannot upgrade past TF 1.9, ensure `sensitive = true` on every
variable and output that touches the secret, and audit the state
backend for encryption at rest plus restrictive IAM (SEC-STATE-001).

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
ephemeral "vault_kv_secret_v2" "creds" {
  mount = "secret"
  name  = "app/db"
}

resource "google_sql_user" "app" {
  name     = "app"
  instance = google_sql_database_instance.app.name
  password = ephemeral.vault_kv_secret_v2.creds.data["password"]
}
```

## Verification

After migration, run `terraform plan` and confirm the secret value does
not appear in the proposed state JSON. `terraform show -json` after
apply should not contain the secret string anywhere under
`values.root_module.resources[*].values`.

## References

**Related rules**
  - [`SEC-SENSITIVE-001`](./SEC-SENSITIVE-001.md)
  - [`SEC-STATE-001`](./SEC-STATE-001.md)

**Source**
  - [`catalog/SEC-EPHEMERAL-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-EPHEMERAL-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-EPHEMERAL-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-EPHEMERAL-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-EPHEMERAL-001
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
