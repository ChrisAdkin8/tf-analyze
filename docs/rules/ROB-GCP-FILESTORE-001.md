---
title: "ROB-GCP-FILESTORE-001 — GCP Filestore instance missing backup configuration"
description: "tf-analyze rule ROB-GCP-FILESTORE-001 (MEDIUM · robustness): GCP Filestore instance missing backup configuration"
keywords: "robustness, medium, terraform, iac, gcp, mitre-T1485, mitre-T1490, cwe-779, nist-csf-pr.ip-4, nist-800-53-cp-9, csa-ccm-bcr-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "ROB-GCP-FILESTORE-001 \u2014 GCP Filestore instance missing backup configuration",
  "description": "Either model `google_filestore_backup` resources on a schedule, or\nattach a `google_filestore_snapshot` via a regularly-run job. For\nEnterprise-tier instances, prefer in-region Cloud Scheduler \u2192\nCloud Run job that calls the Filestore API.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-FILESTORE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/ROB-GCP-FILESTORE-001/"
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
  "keywords": "robustness, medium, terraform, MITRE T1485, MITRE T1490, CWE-779",
  "proficiencyLevel": "Expert",
  "articleSection": "robustness",
  "isAccessibleForFree": true
}
</script>

# 💡 ROB-GCP-FILESTORE-001 — GCP Filestore instance missing backup configuration

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: robustness](https://img.shields.io/badge/section-robustness-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/ROB-GCP-FILESTORE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=ROB-GCP-FILESTORE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add ROB-GCP-FILESTORE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Filestore instance missing backup configuration.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_absent`** on `google_filestore_backup` — _the corpus is missing a resource type we expected to find given other resources present._
  `google_filestore_instance` is declared but no
`google_filestore_backup` resource exists. Filestore has no
automated snapshot/backup policy resource yet — operators must
explicitly model backups in Terraform or accept that the share is
a single point of data loss.

## Why it likely fired

`google_filestore_instance` is declared but no
`google_filestore_backup` resource exists. Filestore has no
automated snapshot/backup policy resource yet — operators must
explicitly model backups in Terraform or accept that the share is
a single point of data loss.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain ROB-GCP-FILESTORE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Either model `google_filestore_backup` resources on a schedule, or
attach a `google_filestore_snapshot` via a regularly-run job. For
Enterprise-tier instances, prefer in-region Cloud Scheduler →
Cloud Run job that calls the Filestore API.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_filestore_backup" "example" {
  name        = "weekly"
  location    = "us-central1"
  source_instance = google_filestore_instance.example.id
  source_file_share = "share1"
}
```

## Verification

```sh
`gcloud filestore backups list --location <l> --filter='source.instance="<inst>"'`
must return at least one recent backup.
```

## References

**PCI-DSS**
  - `Req-3.1`

**SOC 2 Trust Services Criteria**
  - `A1.2`

**MITRE ATT&CK**
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)
  - [`T1490`](https://attack.mitre.org/techniques/T1490/)

**CWE**
  - [`CWE-779`](https://cwe.mitre.org/data/definitions/779.html)

**NIST CSF 2.0**
  - [`PR.IP-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`CP-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cp-9)

**CSA CCM v4**
  - [`BCR-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/ROB-GCP-FILESTORE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/ROB-GCP-FILESTORE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain ROB-GCP-FILESTORE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore ROB-GCP-FILESTORE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - ROB-GCP-FILESTORE-001
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
