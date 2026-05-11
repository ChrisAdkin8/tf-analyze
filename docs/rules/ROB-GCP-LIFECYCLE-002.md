---
title: "ROB-GCP-LIFECYCLE-002 — Stateful resource has force_destroy=true"
description: "tf-analyze rule ROB-GCP-LIFECYCLE-002 (HIGH · robustness): Stateful resource has force_destroy=true"
keywords: "robustness, high, terraform, iac, gcp, mitre-T1485, nist-csf-pr.ip-4, nist-800-53-cm-3, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-GCP-LIFECYCLE-002 \u2014 Stateful resource has force_destroy=true",
  "description": "Set `force_destroy = false` (or remove the argument). With force_destroy\nenabled, a `terraform destroy` will silently delete every object in the\nbucket without asking, even if those objects were uploaded by an\napplication long after the buc",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-LIFECYCLE-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-LIFECYCLE-002/"
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
  "keywords": "robustness, high, terraform, MITRE T1485",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# ⚠️ ROB-GCP-LIFECYCLE-002 — Stateful resource has force_destroy=true

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-GCP-LIFECYCLE-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-GCP-LIFECYCLE-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-GCP-LIFECYCLE-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Stateful resource has force_destroy=true.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `google_storage_bucket` (`force_destroy`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
2. **`resource_arg`** on `google_project` (`force_destroy`) matching `/^true$/` — _the resource declares the named attribute, but its value matches the rule's pattern._

## Why it likely fired

Walk the patterns above against the flagged resource. The detector ran when the listed conditions were satisfied; review the source line in your scan output to see the exact match.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-GCP-LIFECYCLE-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `force_destroy = false` (or remove the argument). With force_destroy
enabled, a `terraform destroy` will silently delete every object in the
bucket without asking, even if those objects were uploaded by an
application long after the bucket was created.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_storage_bucket" "example" {
  name          = "example"
  location      = "US"
  force_destroy = false
}
```

## Verification

Run `terraform plan` and confirm no diff. Manually upload an object
and run `terraform destroy` — it should fail with "bucket is not empty".

## References

**OWASP IaC Cheat Sheet**
  - [`Deploy / Resource Decommissioning Process`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-3)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-GCP-LIFECYCLE-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-GCP-LIFECYCLE-002.yaml) — canonical YAML

## Family

See also rules in the `ROB-GCP-LIFECYCLE-*` family:

- [`ROB-GCP-LIFECYCLE-001`](./ROB-GCP-LIFECYCLE-001.md) — Stateful resource missing lifecycle.prevent_destroy

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-GCP-LIFECYCLE-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-GCP-LIFECYCLE-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-GCP-LIFECYCLE-002
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
