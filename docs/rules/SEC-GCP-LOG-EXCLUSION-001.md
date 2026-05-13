---
title: "SEC-GCP-LOG-EXCLUSION-001 — GCP logging sink with broad exclusion drops audit-relevant entries"
description: "tf-analyze rule SEC-GCP-LOG-EXCLUSION-001 (HIGH · security): GCP logging sink with broad exclusion drops audit-relevant entries"
keywords: "security, high, terraform, iac, gcp, cis-2.8, mitre-T1562.008, cwe-778, d3-iaa, nist-csf-de.cm-1, nist-csf-pr.pt-1, nist-800-53-au-9, nist-800-53-au-12, csa-ccm-log-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-LOG-EXCLUSION-001 \u2014 GCP logging sink with broad exclusion drops audit-relevant entries",
  "description": "Cloud Audit Logs must always reach the long-term sink. Move broad\nexclusions to specific noisy log names (e.g.\n`logName=~\"projects/.*/logs/compute\\\\.googleapis\\\\.com%2Fhealthcheck\"`).",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-LOG-EXCLUSION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-LOG-EXCLUSION-001/"
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
  "keywords": "security, high, terraform, CIS 2.8, MITRE T1562.008, CWE-778, D3-IAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-LOG-EXCLUSION-001 — GCP logging sink with broad exclusion drops audit-relevant entries

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-LOG-EXCLUSION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-LOG-EXCLUSION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-LOG-EXCLUSION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP logging sink with broad exclusion drops audit-relevant entries.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_logging_project_exclusion` matching `/logs/cloudaudit\.googleapis\.com/` — _the resource body matches a regex inside the block._
  `google_logging_project_exclusion.filter` drops Cloud Audit Logs
(admin activity, data access, system event). This blinds
incident response and breaks SOC2 / PCI-DSS audit attestation.
2. **`resource_body_contains`** on `google_logging_project_sink` matching `/exclusions\s*\{[^}]*"cloudaudit\.googleapis\.com/` — _the resource body matches a regex inside the block._
  Project sink exclusion targets cloudaudit.googleapis.com

## Why it likely fired

`google_logging_project_exclusion.filter` drops Cloud Audit Logs
(admin activity, data access, system event). This blinds
incident response and breaks SOC2 / PCI-DSS audit attestation.

Project sink exclusion targets cloudaudit.googleapis.com

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-LOG-EXCLUSION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Cloud Audit Logs must always reach the long-term sink. Move broad
exclusions to specific noisy log names (e.g.
`logName=~"projects/.*/logs/compute\\.googleapis\\.com%2Fhealthcheck"`).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_logging_project_exclusion" "example" {
  name        = "noisy-healthcheck"
  description = "Drop only healthcheck noise"
  filter      = "logName=~\"projects/.*/logs/compute.googleapis.com%2Fhealthcheck\""
}
```

## Verification

```sh
`gcloud logging exclusions list --format='value(name,filter)'` must
not include any filter referencing `cloudaudit.googleapis.com` log
names without an explicit allow-list scope.
```

## References

**CIS Benchmark**
  - `CIS 2.8`

**PCI-DSS**
  - `Req-10.5`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-IAA`](https://d3fend.mitre.org/technique/D3-IAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-9)
  - [`AU-12`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-12)

**CSA CCM v4**
  - [`LOG-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-LOG-EXCLUSION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-LOG-EXCLUSION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-LOG-EXCLUSION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-LOG-EXCLUSION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-LOG-EXCLUSION-001
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
