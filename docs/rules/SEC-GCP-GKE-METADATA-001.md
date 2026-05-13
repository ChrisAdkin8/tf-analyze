---
title: "SEC-GCP-GKE-METADATA-001 — GKE node pool missing GKE_METADATA workload metadata config (SSRF risk)"
description: "tf-analyze rule SEC-GCP-GKE-METADATA-001 (HIGH · security): GKE node pool missing GKE_METADATA workload metadata config (SSRF risk)"
keywords: "security, high, terraform, iac, gcp, cis-5.4.1, mitre-T1552.005, mitre-T1078.004, cwe-918, d3-nta, nist-csf-pr.ac-4, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-GKE-METADATA-001 \u2014 GKE node pool missing GKE_METADATA workload metadata config (SSRF risk)",
  "description": "Enable GKE Metadata Server so pods reach metadata through the\nWorkload Identity broker:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-GKE-METADATA-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-GKE-METADATA-001/"
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
  "keywords": "security, high, terraform, CIS 5.4.1, MITRE T1552.005, MITRE T1078.004, CWE-918, D3-NTA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-GKE-METADATA-001 — GKE node pool missing GKE_METADATA workload metadata config (SSRF risk)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-GKE-METADATA-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-GKE-METADATA-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-GKE-METADATA-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GKE node pool missing GKE_METADATA workload metadata config (SSRF risk).** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_container_node_pool` (`node_config.workload_metadata_config.mode`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_container_node_pool` has no
`node_config.workload_metadata_config.mode = "GKE_METADATA"`.
Without GKE Metadata Server (Workload Identity), every pod on the
node can read the node's compute metadata, including service
account tokens — equivalent to the AWS IMDSv1 SSRF risk
(SEC-AWS-SSRF-001).

## Why it likely fired

`google_container_node_pool` has no
`node_config.workload_metadata_config.mode = "GKE_METADATA"`.
Without GKE Metadata Server (Workload Identity), every pod on the
node can read the node's compute metadata, including service
account tokens — equivalent to the AWS IMDSv1 SSRF risk
(SEC-AWS-SSRF-001).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-GKE-METADATA-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable GKE Metadata Server so pods reach metadata through the
Workload Identity broker:

    resource "google_container_node_pool" "main" {
      # ...
      node_config {
        workload_metadata_config {
          mode = "GKE_METADATA"
        }
      }
    }

Requires the cluster to have `workload_identity_config.workload_pool`
set (see STK-GCP-GKE-002).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_container_node_pool" "example" {
  name       = "main"
  cluster    = google_container_cluster.example.name
  node_count = 1
  node_config {
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
```

## Verification

```sh
`gcloud container node-pools describe <pool> --cluster <c> \
  --format='value(config.workloadMetadataConfig.mode)'` must return
`GKE_METADATA`.
```

## References

**CIS Benchmark**
  - `CIS 5.4.1`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.3`

**MITRE ATT&CK**
  - [`T1552.005`](https://attack.mitre.org/techniques/T1552/005/)
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-918`](https://cwe.mitre.org/data/definitions/918.html)

**MITRE D3FEND**
  - [`D3-NTA`](https://d3fend.mitre.org/technique/D3-NTA/)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-GKE-METADATA-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-GKE-METADATA-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-GKE-METADATA-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-GKE-METADATA-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-GKE-METADATA-001
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
