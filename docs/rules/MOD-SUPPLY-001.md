---
title: "MOD-SUPPLY-001 — Module pinned to mutable git ref (main or master)"
description: "tf-analyze rule MOD-SUPPLY-001 (HIGH · module): Module pinned to mutable git ref (main or master)"
keywords: "module, high, terraform, iac, mitre-T1195.002, cwe-1357, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-3, csa-ccm-sta-04, slsa-l2, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-SUPPLY-001 \u2014 Module pinned to mutable git ref (main or master)",
  "description": "Replace `?ref=main` with a full commit SHA or semver tag:\n  source = \"git::https://github.com/org/module.git?ref=v1.2.3\"\nMutable refs can silently introduce breaking changes or malicious code\non the next `terraform init -upgrade`.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-001/"
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
  "keywords": "module, high, terraform, MITRE T1195.002, CWE-1357, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "module",
  "isAccessibleForFree": true
}
</script>

# ⚠️ MOD-SUPPLY-001 — Module pinned to mutable git ref (main or master)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-SUPPLY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-SUPPLY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-SUPPLY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module pinned to mutable git ref (main or master).** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"[^"]*\?ref=(main|master)"/` — _a textual regex matched somewhere in the file._
  Module source URL contains ?ref=main or ?ref=master

## Why it likely fired

Module source URL contains ?ref=main or ?ref=master

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-SUPPLY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `?ref=main` with a full commit SHA or semver tag:
  source = "git::https://github.com/org/module.git?ref=v1.2.3"
Mutable refs can silently introduce breaking changes or malicious code
on the next `terraform init -upgrade`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
module "example" {
  source = "git::https://github.com/example/module.git?ref=v1.2.3"
}
```

## Verification

Verify all git-sourced module URLs use a pinned tag or SHA, not main/master.

## References

**SOC 2 Trust Services Criteria**
  - `CC9.2`

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Open Source Dependency Scanning`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-3)

**CSA CCM v4**
  - [`STA-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA L2`](https://slsa.dev/spec/v1.0/levels#l2)
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/MOD-SUPPLY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-SUPPLY-001.yaml) — canonical YAML

## Family

See also rules in the `MOD-SUPPLY-*` family:

- [`MOD-SUPPLY-002`](./MOD-SUPPLY-002.md) — Module uses raw git source instead of registry
- [`MOD-SUPPLY-003`](./MOD-SUPPLY-003.md) — Registry module missing version constraint
- [`MOD-SUPPLY-004`](./MOD-SUPPLY-004.md) — Module version constraint uses `>=` with no upper bound

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-SUPPLY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-SUPPLY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-SUPPLY-001
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
