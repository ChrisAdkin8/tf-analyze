---
title: "SEC-SENSITIVE-PATTERN-001 — Credential-shaped variable not marked sensitive=true"
description: "tf-analyze rule SEC-SENSITIVE-PATTERN-001 (HIGH · security): Credential-shaped variable not marked sensitive=true"
keywords: "security, high, terraform, iac, mitre-T1552.001, mitre-T1552.004, nist-csf-pr.ds-5, nist-800-53-sc-28, csa-ccm-cek-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-SENSITIVE-PATTERN-001 \u2014 Credential-shaped variable not marked sensitive=true",
  "description": "Add `sensitive = true` to the variable block. If the value is set\nvia `*.tfvars`, the file itself should be excluded from version\ncontrol and stored in a dedicated secrets store (HashiCorp Vault,\nAWS Secrets Manager, GCP Secret Manager, Azu",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SENSITIVE-PATTERN-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SENSITIVE-PATTERN-001/"
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
  "keywords": "security, high, terraform, MITRE T1552.001, MITRE T1552.004",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-SENSITIVE-PATTERN-001 — Credential-shaped variable not marked sensitive=true

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-SENSITIVE-PATTERN-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-SENSITIVE-PATTERN-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-SENSITIVE-PATTERN-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Credential-shaped variable not marked sensitive=true.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`variable_credential_pattern`** — _a `variable_credential_pattern` pattern._
  Variable name matches a credential-shaped pattern (`*_password`,
`*_token`, `*_secret`, `*_key`, `*_apikey`, `*_credential`,
`*_auth`) but the variable block does not include
`sensitive = true`. Without that marker Terraform will print the
value in `terraform plan` and `terraform output` console output —
a class of credential leak that ends up in CI logs and PR-bot
comments. The pattern set is intentionally narrow (suffix-anchored)
to avoid false positives on names like `key_arn` or
`secret_id` that refer to identifiers rather than secret values.

## Why it likely fired

Variable name matches a credential-shaped pattern (`*_password`,
`*_token`, `*_secret`, `*_key`, `*_apikey`, `*_credential`,
`*_auth`) but the variable block does not include
`sensitive = true`. Without that marker Terraform will print the
value in `terraform plan` and `terraform output` console output —
a class of credential leak that ends up in CI logs and PR-bot
comments. The pattern set is intentionally narrow (suffix-anchored)
to avoid false positives on names like `key_arn` or
`secret_id` that refer to identifiers rather than secret values.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SENSITIVE-PATTERN-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `sensitive = true` to the variable block. If the value is set
via `*.tfvars`, the file itself should be excluded from version
control and stored in a dedicated secrets store (HashiCorp Vault,
AWS Secrets Manager, GCP Secret Manager, Azure Key Vault) — the
variable definition just declares the contract; provisioning is
out-of-band.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
variable "db_password" {
  type        = string
  sensitive   = true
  description = "Database password — supplied via TF_VAR_db_password or a secrets-manager data source."
}
```

## Verification

Run `terraform plan` and confirm any value derived from this
variable is rendered as `<sensitive>`. Re-run tf-analyze in
`mode:verify-fixed` to confirm the rule no longer fires.

## References

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Secrets Detection`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
  - [`Develop and Distribute / Secrets Storage Management`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)
  - [`T1552.004`](https://attack.mitre.org/techniques/T1552/004/)

**NIST CSF 2.0**
  - [`PR.DS-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-SENSITIVE-PATTERN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SENSITIVE-PATTERN-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SENSITIVE-PATTERN-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SENSITIVE-PATTERN-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SENSITIVE-PATTERN-001
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
