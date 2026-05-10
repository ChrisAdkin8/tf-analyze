---
title: "SEC-SENSITIVE-003 — Sensitive variable passed to templatefile()"
description: "tf-analyze rule SEC-SENSITIVE-003 (HIGH · security): Sensitive variable passed to templatefile()"
keywords: "security, high, terraform, iac, mitre-T1552.001, cwe-200, d3-ch"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-SENSITIVE-003 \u2014 Sensitive variable passed to templatefile()",
  "description": "Avoid passing sensitive variables through `templatefile()`. The\nrendered output is a plain string that Terraform does NOT mark as\nsensitive, so it appears in plans, state, and logs.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SENSITIVE-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SENSITIVE-003/"
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
  "keywords": "security, high, terraform, MITRE T1552.001, CWE-200, D3-CH",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-SENSITIVE-003 — Sensitive variable passed to templatefile()

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-SENSITIVE-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-SENSITIVE-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-SENSITIVE-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Sensitive variable passed to templatefile().** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`templatefile_sensitive_leak`** — _a `templatefile()` call passes a sensitive variable to a template._
  templatefile() call whose argument map references a sensitive variable, rendering the secret into a non-sensitive string

## Why it likely fired

templatefile() call whose argument map references a sensitive variable, rendering the secret into a non-sensitive string

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SENSITIVE-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Avoid passing sensitive variables through `templatefile()`. The
rendered output is a plain string that Terraform does NOT mark as
sensitive, so it appears in plans, state, and logs.

Instead, use a `local` to construct the sensitive portion separately
and mark it `sensitive = true`, or use `nonsensitive()` explicitly
to acknowledge the exposure.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Separate sensitive values — don't pass them through templatefile()
locals {
  # Non-sensitive config rendered by templatefile
  user_data = templatefile("${path.module}/init.sh.tpl", {
    region = var.region
    name   = var.name
  })
}

# Pass password separately via a write_only argument or secrets manager reference
resource "aws_instance" "app" {
  user_data = local.user_data
  # password is injected via metadata or secrets manager, not template
}
```

## Verification

Run `terraform plan` and check that the rendered template value
shows as `(sensitive value)` in the plan output. If it shows in
cleartext, the leak is confirmed.

## References

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Secrets Detection`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-200`](https://cwe.mitre.org/data/definitions/200.html)

**MITRE D3FEND**
  - [`D3-CH`](https://d3fend.mitre.org/technique/D3-CH/)

**Source**
  - [`catalog/SEC-SENSITIVE-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SENSITIVE-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-SENSITIVE-*` family:

- [`SEC-SENSITIVE-001`](./SEC-SENSITIVE-001.md) — Sensitive output not marked sensitive=true
- [`SEC-SENSITIVE-002`](./SEC-SENSITIVE-002.md) — Sensitive marker dropped at module boundary

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SENSITIVE-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SENSITIVE-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SENSITIVE-003
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
