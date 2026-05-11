---
title: "MOD-SUPPLY-002 — Module uses raw git source instead of registry"
description: "tf-analyze rule MOD-SUPPLY-002 (LOW · module): Module uses raw git source instead of registry"
keywords: "module, low, terraform, iac, mitre-T1195.002, cwe-1357, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-3, csa-ccm-sta-04, slsa-l2, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-SUPPLY-002 \u2014 Module uses raw git source instead of registry",
  "description": "Prefer Terraform Registry sources (`namespace/module/provider`) over raw\ngit URLs. Registry modules are integrity-hashed in `.terraform.lock.hcl`;\nraw git sources bypass the digest check.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-SUPPLY-002/"
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
  "keywords": "module, low, terraform, MITRE T1195.002, CWE-1357, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "module",
  "isAccessibleForFree": true
}
</script>

# ℹ️ MOD-SUPPLY-002 — Module uses raw git source instead of registry

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-SUPPLY-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-SUPPLY-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-SUPPLY-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module uses raw git source instead of registry.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"git::/` — _a textual regex matched somewhere in the file._
  Module sourced from raw git URL rather than Terraform Registry

## Why it likely fired

Module sourced from raw git URL rather than Terraform Registry

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-SUPPLY-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Prefer Terraform Registry sources (`namespace/module/provider`) over raw
git URLs. Registry modules are integrity-hashed in `.terraform.lock.hcl`;
raw git sources bypass the digest check.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Before: module sourced from raw git
# source = "git::https://github.com/example/terraform-aws-vpc.git"

# After: registry source with version pin
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
```

## Verification

Replace `git::` sources with registry equivalents where available.

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
  - [`catalog/MOD-SUPPLY-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-SUPPLY-002.yaml) — canonical YAML

## Family

See also rules in the `MOD-SUPPLY-*` family:

- [`MOD-SUPPLY-001`](./MOD-SUPPLY-001.md) — Module pinned to mutable git ref (main or master)
- [`MOD-SUPPLY-003`](./MOD-SUPPLY-003.md) — Registry module missing version constraint
- [`MOD-SUPPLY-004`](./MOD-SUPPLY-004.md) — Module version constraint uses `>=` with no upper bound

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-SUPPLY-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-SUPPLY-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-SUPPLY-002
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
