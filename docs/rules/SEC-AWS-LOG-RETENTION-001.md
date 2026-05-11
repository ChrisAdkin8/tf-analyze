---
title: "SEC-AWS-LOG-RETENTION-001 — Log bucket missing object_lock_configuration with retention >= 90 days"
description: "tf-analyze rule SEC-AWS-LOG-RETENTION-001 (HIGH · security): Log bucket missing object_lock_configuration with retention >= 90 days"
keywords: "security, high, terraform, iac, aws, cis-3.x, mitre-T1070.001, mitre-T1485, cwe-778, cwe-693, nist-csf-pr.pt-1, nist-800-53-au-11, csa-ccm-log-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-LOG-RETENTION-001 \u2014 Log bucket missing object_lock_configuration with retention >= 90 days",
  "description": "resource \"aws_s3_bucket\" \"audit_logs\" {\n  bucket              = \"my-audit-logs\"\n  object_lock_enabled = true\n}",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-LOG-RETENTION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-LOG-RETENTION-001/"
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
  "keywords": "security, high, terraform, CIS 3.x, MITRE T1070.001, MITRE T1485, CWE-778, CWE-693",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-LOG-RETENTION-001 — Log bucket missing object_lock_configuration with retention >= 90 days

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-LOG-RETENTION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-LOG-RETENTION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-LOG-RETENTION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Log bucket missing object_lock_configuration with retention >= 90 days.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_s3_bucket` (`object_lock_enabled`) — _the resource is missing a required attribute (or nested attribute path)._
  An S3 bucket whose name suggests it holds audit/access logs
must have object-lock enabled with a retention period of at
least 90 days. Without object-lock, an attacker (or careless
operator) with `s3:DeleteObject` can erase the audit trail
that would otherwise expose them. CIS 3.x + NIST SP 800-53
AU-11 (Audit Record Retention) both require this. 90 days is
the floor for SOC 2 CC7.x; many regulators require longer.

## Why it likely fired

An S3 bucket whose name suggests it holds audit/access logs
must have object-lock enabled with a retention period of at
least 90 days. Without object-lock, an attacker (or careless
operator) with `s3:DeleteObject` can erase the audit trail
that would otherwise expose them. CIS 3.x + NIST SP 800-53
AU-11 (Audit Record Retention) both require this. 90 days is
the floor for SOC 2 CC7.x; many regulators require longer.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-LOG-RETENTION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

resource "aws_s3_bucket" "audit_logs" {
  bucket              = "my-audit-logs"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 90  # increase per your retention policy
    }
  }
}

## Verification

```sh
`aws s3api get-object-lock-configuration --bucket <name>` should
return a mode of `GOVERNANCE` or `COMPLIANCE` with `Days >= 90`.
```

## References

**CIS Benchmark**
  - `CIS 3.x`

**MITRE ATT&CK**
  - [`T1070.001`](https://attack.mitre.org/techniques/T1070/001/)
  - [`T1485`](https://attack.mitre.org/techniques/T1485/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)
  - [`CWE-693`](https://cwe.mitre.org/data/definitions/693.html)

**NIST CSF 2.0**
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-11`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-11)

**CSA CCM v4**
  - [`LOG-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-LOG-RETENTION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-LOG-RETENTION-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-LOG-RETENTION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-LOG-RETENTION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-LOG-RETENTION-001
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
