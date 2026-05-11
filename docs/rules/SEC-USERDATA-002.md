---
title: "SEC-USERDATA-002 — user_data passes a sensitive var unencoded (base64encode missing)"
description: "tf-analyze rule SEC-USERDATA-002 (MEDIUM · security): user_data passes a sensitive var unencoded (base64encode missing)"
keywords: "security, medium, terraform, iac, mitre-T1552.001, cwe-200, nist-csf-pr.ds-1, nist-csf-pr.ds-2, nist-800-53-sc-28, csa-ccm-dsi-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-USERDATA-002 \u2014 user_data passes a sensitive var unencoded (base64encode missing)",
  "description": "Don't assign secrets directly to user_data. Pull from Parameter\nStore / Secrets Manager via the instance IAM role. If a runtime\npass is unavoidable, encode and template:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-USERDATA-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-USERDATA-002/"
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
  "keywords": "security, medium, terraform, MITRE T1552.001, CWE-200",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-USERDATA-002 — user_data passes a sensitive var unencoded (base64encode missing)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-USERDATA-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-USERDATA-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-USERDATA-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **user_data passes a sensitive var unencoded (base64encode missing).** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/user_data\s*=\s*var\.(password|secret|token|api_key|key)\b/` — _a textual regex matched somewhere in the file._
  Assigning a sensitive variable straight to `user_data` (without
`base64encode(...)` and without a template) means the secret
gets stored verbatim on the instance metadata service — easier
to read, easier to leak via `aws-cli ec2 describe-instance-attribute`.

## Why it likely fired

Assigning a sensitive variable straight to `user_data` (without
`base64encode(...)` and without a template) means the secret
gets stored verbatim on the instance metadata service — easier
to read, easier to leak via `aws-cli ec2 describe-instance-attribute`.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-USERDATA-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Don't assign secrets directly to user_data. Pull from Parameter
Store / Secrets Manager via the instance IAM role. If a runtime
pass is unavoidable, encode and template:

    user_data = base64encode(
      templatefile("${path.module}/init.sh.tpl", {
        arn = aws_secretsmanager_secret.app.arn
      })
    )

And keep the secret out of state by sourcing via `data "aws_secretsmanager_secret_version"`.

## Verification

```sh
`grep -rE 'user_data\s*=\s*var\.' --include="*.tf"`. Confirm each
match is either a non-secret string or wrapped in `base64encode + templatefile`.
```

## References

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-200`](https://cwe.mitre.org/data/definitions/200.html)

**NIST CSF 2.0**
  - [`PR.DS-1`](https://www.nist.gov/cyberframework)
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`DSI-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `A02`

**Source**
  - [`catalog/SEC-USERDATA-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-USERDATA-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-USERDATA-*` family:

- [`SEC-USERDATA-001`](./SEC-USERDATA-001.md) — user_data templates a sensitive var or contains a curl\|bash pattern

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-USERDATA-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-USERDATA-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-USERDATA-002
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
