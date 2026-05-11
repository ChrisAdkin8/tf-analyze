---
title: "SEC-SENSITIVE-001 — Sensitive output not marked sensitive=true"
description: "tf-analyze rule SEC-SENSITIVE-001 (HIGH · security): Sensitive output not marked sensitive=true"
keywords: "security, high, terraform, iac, mitre-T1552.001, cwe-200, cwe-532, d3-ch, nist-csf-pr.ds-5, nist-800-53-sc-28, csa-ccm-cek-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-SENSITIVE-001 \u2014 Sensitive output not marked sensitive=true",
  "description": "Add `sensitive = true` to the output block. Without this marker the\nvalue appears in `terraform plan` and `terraform output` console\noutput and may end up in CI logs.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SENSITIVE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SENSITIVE-001/"
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
  "keywords": "security, high, terraform, MITRE T1552.001, CWE-200, CWE-532, D3-CH",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-SENSITIVE-001 — Sensitive output not marked sensitive=true

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-SENSITIVE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-SENSITIVE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-SENSITIVE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Sensitive output not marked sensitive=true.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`output_sensitive_leak`** — _a `output_sensitive_leak` pattern._
  Output value references a variable marked sensitive=true but the
output itself does not have sensitive=true.

## Why it likely fired

Output value references a variable marked sensitive=true but the
output itself does not have sensitive=true.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SENSITIVE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add `sensitive = true` to the output block. Without this marker the
value appears in `terraform plan` and `terraform output` console
output and may end up in CI logs.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
output "db_password" {
  value     = module.db.password
  sensitive = true
}
```

## Verification

Run `terraform output <name>` and confirm the value is masked as
`<sensitive>`. Re-run tf-analyze in mode:verify-fixed.

## References

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Secrets Detection`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-200`](https://cwe.mitre.org/data/definitions/200.html)
  - [`CWE-532`](https://cwe.mitre.org/data/definitions/532.html)

**MITRE D3FEND**
  - [`D3-CH`](https://d3fend.mitre.org/technique/D3-CH/)

**NIST CSF 2.0**
  - [`PR.DS-5`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-28`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-28)

**CSA CCM v4**
  - [`CEK-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-SENSITIVE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SENSITIVE-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-SENSITIVE-*` family:

- [`SEC-SENSITIVE-002`](./SEC-SENSITIVE-002.md) — Sensitive marker dropped at module boundary
- [`SEC-SENSITIVE-003`](./SEC-SENSITIVE-003.md) — Sensitive variable passed to templatefile()

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SENSITIVE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SENSITIVE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SENSITIVE-001
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
