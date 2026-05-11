---
title: "ROB-VERSION-002 — Submodule directory has no required_version"
description: "tf-analyze rule ROB-VERSION-002 (LOW · robustness): Submodule directory has no required_version"
keywords: "robustness, low, terraform, iac, mitre-T1195.002, cwe-1357, d3-sca, nist-csf-id.sc-2, nist-csf-pr.ip-1, nist-800-53-cm-2, nist-800-53-sr-3, csa-ccm-sta-04, csa-ccm-ccc-05, slsa-l1, slsa-source"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-VERSION-002 \u2014 Submodule directory has no required_version",
  "description": "Submodules inherit the root's Terraform version *implicitly*. That hides\nfeature-level assumptions: a submodule using `optional()` object attrs or\n`moved {}` blocks will silently break if the root drops to pre-1.3 /\npre-1.1. Declare:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-VERSION-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-VERSION-002/"
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
  "keywords": "robustness, low, terraform, MITRE T1195.002, CWE-1357, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ℹ️ ROB-VERSION-002 — Submodule directory has no required_version

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-VERSION-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-VERSION-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-VERSION-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Submodule directory has no required_version.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`submodule_version_missing`** — _a `submodule_version_missing` pattern._
  A submodule directory (.tf present) has no required_version constraint anywhere

## Why it likely fired

A submodule directory (.tf present) has no required_version constraint anywhere

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-VERSION-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Submodules inherit the root's Terraform version *implicitly*. That hides
feature-level assumptions: a submodule using `optional()` object attrs or
`moved {}` blocks will silently break if the root drops to pre-1.3 /
pre-1.1. Declare:

```hcl
terraform {
  required_version = ">= 1.6"
}
```

in each submodule so `terraform get` fails fast on unsupported versions.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
terraform {
  required_version = ">= 1.6, < 2.0"
}
```

## Verification

Run `terraform init` inside the submodule directory (if it is callable
in isolation) — it should enforce the new constraint.

## References

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Version Control Discipline`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)
  - [`PR.IP-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-2)
  - [`SR-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-3)

**CSA CCM v4**
  - [`STA-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`CCC-05`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA L1`](https://slsa.dev/spec/v1.0/levels#l1)
  - [`SLSA source`](https://slsa.dev/spec/v1.0/source-track)

**Source**
  - [`catalog/ROB-VERSION-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-VERSION-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-VERSION-*` family:

- [`ROB-VERSION-001`](./ROB-VERSION-001.md) — required_version floor too old for skill assumptions
- [`ROB-VERSION-003`](./ROB-VERSION-003.md) — required_providers entry missing version constraint

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-VERSION-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-VERSION-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-VERSION-002
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
