---
title: "SEC-GCP-SECRET-001 — GCP Secret Manager secret has no rotation configured"
description: "tf-analyze rule SEC-GCP-SECRET-001 (MEDIUM · security): GCP Secret Manager secret has no rotation configured"
keywords: "security, medium, terraform, iac, gcp, cis-1.7, mitre-T1552.001, cwe-798, d3-cr, nist-csf-pr.ac-1, nist-800-53-ia-5, csa-ccm-cek-12"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-SECRET-001 \u2014 GCP Secret Manager secret has no rotation configured",
  "description": "Configure automatic rotation via a Pub/Sub-driven rotator:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SECRET-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SECRET-001/"
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
  "keywords": "security, medium, terraform, CIS 1.7, MITRE T1552.001, CWE-798, D3-CR",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-GCP-SECRET-001 — GCP Secret Manager secret has no rotation configured

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-SECRET-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-GCP-SECRET-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-GCP-SECRET-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GCP Secret Manager secret has no rotation configured.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `google_secret_manager_secret` (`rotation`) — _the resource is missing a required attribute (or nested attribute path)._
  `google_secret_manager_secret` has no `rotation` block. Long-lived
secrets accumulate blast radius — a leaked credential that is
never rotated provides indefinite access. Equivalent to the AWS
Secrets Manager rotation gap (ROB-AWS-SECRETSMANAGER-001).

## Why it likely fired

`google_secret_manager_secret` has no `rotation` block. Long-lived
secrets accumulate blast radius — a leaked credential that is
never rotated provides indefinite access. Equivalent to the AWS
Secrets Manager rotation gap (ROB-AWS-SECRETSMANAGER-001).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-SECRET-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Configure automatic rotation via a Pub/Sub-driven rotator:

    resource "google_pubsub_topic" "rotator" {
      name = "secret-rotator"
    }

    resource "google_secret_manager_secret" "db_pw" {
      secret_id = "db-pw"
      replication { auto {} }
      topics { name = google_pubsub_topic.rotator.id }
      rotation {
        next_rotation_time = "2026-07-01T00:00:00Z"
        rotation_period    = "2592000s"   # 30 days
      }
    }

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "google_secret_manager_secret" "example" {
  secret_id = "db-pw"
  replication { auto {} }
  topics { name = "projects/example/topics/secret-rotator" }
  rotation {
    next_rotation_time = "2026-07-01T00:00:00Z"
    rotation_period    = "2592000s"
  }
}
```

## Verification

```sh
`gcloud secrets describe <name> --format='value(rotation.rotationPeriod)'`
must return a non-zero duration.
```

## References

**CIS Benchmark**
  - `CIS 1.7`

**PCI-DSS**
  - `Req-3.6`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-798`](https://cwe.mitre.org/data/definitions/798.html)

**MITRE D3FEND**
  - [`D3-CR`](https://d3fend.mitre.org/technique/D3-CR/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)

**CSA CCM v4**
  - [`CEK-12`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-GCP-SECRET-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-SECRET-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-GCP-SECRET-*` family:

- [`SEC-GCP-SECRET-002`](./SEC-GCP-SECRET-002.md) — GCP Secret Manager secret without CMEK on user-managed replication

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-SECRET-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-SECRET-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-SECRET-001
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
