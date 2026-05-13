---
title: "STK-GCP-CLOUDBUILD-001 — GCP Cloud Build trigger missing manual approval"
description: "tf-analyze rule STK-GCP-CLOUDBUILD-001 (MEDIUM · stack): GCP Cloud Build trigger missing manual approval"
keywords: "stack, medium, terraform, iac, gcp, mitre-T1195.002, cwe-1357, nist-csf-pr.ip-3, nist-800-53-cm-3, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-CLOUDBUILD-001 \u2014 GCP Cloud Build trigger missing manual approval",
  "description": "Gate production trigger runs on manual approval:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDBUILD-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-CLOUDBUILD-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1195.002, CWE-1357",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-GCP-CLOUDBUILD-001 — GCP Cloud Build trigger missing manual approval

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-CLOUDBUILD-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-CLOUDBUILD-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-CLOUDBUILD-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Cloud Build trigger missing manual approval.** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_cloudbuild_trigger` (`approval_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_cloudbuild_trigger` has no `approval_config`. Every push to
the source branch produces an image and may deploy automatically.
For production-bound triggers, a human approver should gate the
run. Equivalent to SLSA Build Track Level 3's "two-party review"
control.

## Why it likely fired

`google_cloudbuild_trigger` has no `approval_config`. Every push to
the source branch produces an image and may deploy automatically.
For production-bound triggers, a human approver should gate the
run. Equivalent to SLSA Build Track Level 3's "two-party review"
control.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-CLOUDBUILD-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Gate production trigger runs on manual approval:

    resource "google_cloudbuild_trigger" "prod" {
      # ...
      approval_config {
        approval_required = true
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_cloudbuild_trigger" "example" {
  name        = "prod-deploy"
  filename    = "cloudbuild.yaml"
  description = "Production deployment"
  github {
    owner = "example"
    name  = "infra"
    push {
      branch = "^main$"
    }
  }
  approval_config {
    approval_required = true
  }
}
```

## Verification

```sh
`gcloud builds triggers describe <name> --format='value(approvalConfig.approvalRequired)'`
must return `True` for production-bound triggers.
```

## References

**PCI-DSS**
  - `Req-6.4`

**SOC 2 Trust Services Criteria**
  - `CC8.1`

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)

**NIST CSF 2.0**
  - [`PR.IP-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CM-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-3)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-GCP-CLOUDBUILD-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-CLOUDBUILD-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-CLOUDBUILD-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-CLOUDBUILD-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-CLOUDBUILD-001
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
