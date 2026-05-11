---
title: "ROB-DRIFT-001 — Resource uses ignore_changes = all"
description: "tf-analyze rule ROB-DRIFT-001 (HIGH · robustness): Resource uses ignore_changes = all"
keywords: "robustness, high, terraform, iac, mitre-T1562.001, cwe-693, nist-csf-pr.ip-3, nist-800-53-cm-3, nist-800-53-cm-6, csa-ccm-ccc-05"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-DRIFT-001 \u2014 Resource uses ignore_changes = all",
  "description": "Replace `ignore_changes = all` with an explicit list of the specific\nattributes that must be ignored. The nuclear option masks legitimate drift\nand makes it impossible to detect when a resource has been modified\noutside Terraform.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-DRIFT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-DRIFT-001/"
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
  "keywords": "robustness, high, terraform, MITRE T1562.001, CWE-693",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-DRIFT-001 — Resource uses ignore_changes = all

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-DRIFT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-DRIFT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-DRIFT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Resource uses ignore_changes = all.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`grep`** matching `/(?m)^\s*ignore_changes\s*=\s*all\s*$/` — _a textual regex matched somewhere in the file._
  lifecycle block with ignore_changes = all masks all drift

## Why it likely fired

lifecycle block with ignore_changes = all masks all drift

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-DRIFT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace `ignore_changes = all` with an explicit list of the specific
attributes that must be ignored. The nuclear option masks legitimate drift
and makes it impossible to detect when a resource has been modified
outside Terraform.

If the resource is truly unmanageable by Terraform, document WHY in a
comment and consider whether it should be removed from Terraform state
entirely.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_autoscaling_group" "example" {
  name = "example"
  lifecycle {
    ignore_changes = [
      desired_capacity,
      tag,
    ]
  }
}
```

## Verification

Run `terraform plan` after narrowing the ignore list. Any new diff lines
are real drift that was previously hidden.

## References

**OWASP IaC Cheat Sheet**
  - [`Runtime / Immutable Infrastructure Model`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1562.001`](https://attack.mitre.org/techniques/T1562/001/)

**CWE**
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**NIST CSF 2.0**
  - [`PR.IP-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-3)
  - [`CM-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-6)

**CSA CCM v4**
  - [`CCC-05`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-DRIFT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-DRIFT-001.yaml) — canonical YAML

## Family

See also rules in the `ROB-DRIFT-*` family:

- [`ROB-DRIFT-002`](./ROB-DRIFT-002.md) — ignore_changes hides too much (wildcard, or tags-wide on a tagged resource)
- [`ROB-DRIFT-003`](./ROB-DRIFT-003.md) — ignore_changes lists too many attributes (drift-disable by attrition)

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-DRIFT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-DRIFT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-DRIFT-001
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
