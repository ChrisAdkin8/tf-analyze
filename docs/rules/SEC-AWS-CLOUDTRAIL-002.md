---
title: "SEC-AWS-CLOUDTRAIL-002 — CloudTrail log file integrity validation disabled"
description: "tf-analyze rule SEC-AWS-CLOUDTRAIL-002 (HIGH · security): CloudTrail log file integrity validation disabled"
keywords: "security, high, terraform, iac, aws, cis-3.2, mitre-T1562.008, cwe-778, d3-faa, nist-csf-de.cm-1, nist-csf-de.ae-3, nist-800-53-au-2, nist-800-53-au-9, csa-ccm-log-02"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-CLOUDTRAIL-002 \u2014 CloudTrail log file integrity validation disabled",
  "description": "Enable log file validation on every CloudTrail trail:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-CLOUDTRAIL-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-CLOUDTRAIL-002/"
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
  "keywords": "security, high, terraform, CIS 3.2, MITRE T1562.008, CWE-778, D3-FAA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-CLOUDTRAIL-002 — CloudTrail log file integrity validation disabled

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-CLOUDTRAIL-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-CLOUDTRAIL-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-CLOUDTRAIL-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **CloudTrail log file integrity validation disabled.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cloudtrail` (`enable_log_file_validation`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_cloudtrail` without `enable_log_file_validation`. An attacker
who gains write access to the CloudTrail S3 bucket can edit or
delete log files to erase evidence of their activity. Without
validation, tampered logs are indistinguishable from authentic ones.
2. **`hcl_attr`** on `aws_cloudtrail` (`enable_log_file_validation`) not equal to `True` — _an attribute value differs from the expected literal._
  `enable_log_file_validation = false` disables the SHA-256 hash
chain that makes log tampering detectable.

## Why it likely fired

`aws_cloudtrail` without `enable_log_file_validation`. An attacker
who gains write access to the CloudTrail S3 bucket can edit or
delete log files to erase evidence of their activity. Without
validation, tampered logs are indistinguishable from authentic ones.

`enable_log_file_validation = false` disables the SHA-256 hash
chain that makes log tampering detectable.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-CLOUDTRAIL-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Enable log file validation on every CloudTrail trail:

    resource "aws_cloudtrail" "org" {
      name                       = "org-trail"
      s3_bucket_name             = aws_s3_bucket.trail.id
      enable_log_file_validation = true
      is_multi_region_trail      = true
      kms_key_id                 = aws_kms_key.trail.arn
    }

Validation works by CloudTrail computing a SHA-256 digest file every
hour and signing it with a private key. To verify integrity retroactively:
`aws cloudtrail validate-logs --trail-arn <arn> --start-time <ISO8601>`.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_cloudtrail" "example" {
  # ... other arguments ...
  enable_log_file_validation = true
}
```

## Verification

```sh
`aws cloudtrail describe-trails --trail-name-list <name> \
  --query 'trailList[0].LogFileValidationEnabled'`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 3.2`

**PCI-DSS**
  - `Req-10.5`

**SOC 2 Trust Services Criteria**
  - `CC7.2`

**OWASP IaC Cheat Sheet**
  - [`Runtime / Comprehensive Logging Enablement`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1562.008`](https://attack.mitre.org/techniques/T1562/008/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**MITRE D3FEND**
  - [`D3-FAA`](https://d3fend.mitre.org/technique/D3-FAA/)

**NIST CSF 2.0**
  - [`DE.CM-1`](https://www.nist.gov/cyberframework)
  - [`DE.AE-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-2`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-2)
  - [`AU-9`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-9)

**CSA CCM v4**
  - [`LOG-02`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-CLOUDTRAIL-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-CLOUDTRAIL-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-CLOUDTRAIL-*` family:

- [`SEC-AWS-CLOUDTRAIL-001`](./SEC-AWS-CLOUDTRAIL-001.md) — CloudTrail not enabled for all regions

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-CLOUDTRAIL-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-CLOUDTRAIL-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-CLOUDTRAIL-002
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
