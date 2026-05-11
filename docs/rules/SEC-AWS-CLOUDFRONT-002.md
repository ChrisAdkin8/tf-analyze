---
title: "SEC-AWS-CLOUDFRONT-002 — CloudFront distribution missing access logging"
description: "tf-analyze rule SEC-AWS-CLOUDFRONT-002 (MEDIUM · security): CloudFront distribution missing access logging"
keywords: "security, medium, terraform, iac, aws, mitre-T1071.001, cwe-319, d3-ei, nist-csf-pr.ds-2, nist-800-53-sc-8, nist-800-53-sc-8-1, csa-ccm-cek-06"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-CLOUDFRONT-002 \u2014 CloudFront distribution missing access logging",
  "description": "Add a `logging_config` block pointing to an S3 bucket:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-CLOUDFRONT-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-CLOUDFRONT-002/"
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
  "keywords": "security, medium, terraform, MITRE T1071.001, CWE-319, D3-EI",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-CLOUDFRONT-002 — CloudFront distribution missing access logging

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-CLOUDFRONT-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-CLOUDFRONT-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-CLOUDFRONT-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **CloudFront distribution missing access logging.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `aws_cloudfront_distribution` (`logging_config`) — _the resource is missing a required attribute (or nested attribute path)._
  `aws_cloudfront_distribution` has no `logging_config` block.
Without access logging, viewer IP addresses, requested paths,
cache-hit/miss status, bytes transferred, and HTTP status codes
are not recorded. Post-incident forensics and abuse investigation
have no CloudFront-layer evidence.

## Why it likely fired

`aws_cloudfront_distribution` has no `logging_config` block.
Without access logging, viewer IP addresses, requested paths,
cache-hit/miss status, bytes transferred, and HTTP status codes
are not recorded. Post-incident forensics and abuse investigation
have no CloudFront-layer evidence.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-CLOUDFRONT-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Add a `logging_config` block pointing to an S3 bucket:

    resource "aws_cloudfront_distribution" "cdn" {
      logging_config {
        bucket          = aws_s3_bucket.cf_logs.bucket_domain_name
        include_cookies = false
        prefix          = "cf/"
      }
      # ...
    }

Grant the CloudFront logging principal `s3:PutObject` on the target
bucket via a bucket policy. Enable versioning and lifecycle rules on
the log bucket — CloudFront generates high log volume.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_cloudfront_distribution" "example" {
  # ... other arguments ...
  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront/"
  }
}
```

## Verification

```sh
`aws cloudfront get-distribution --id <id> \
  --query 'Distribution.DistributionConfig.Logging.Enabled'`
must return `true`.
```

## References

**MITRE ATT&CK**
  - [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/)

**CWE**
  - [`CWE-319`](https://cwe.mitre.org/data/definitions/319.html)

**MITRE D3FEND**
  - [`D3-EI`](https://d3fend.mitre.org/technique/D3-EI/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-8`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8)
  - [`SC-8(1)`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-8-1)

**CSA CCM v4**
  - [`CEK-06`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-CLOUDFRONT-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-CLOUDFRONT-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-CLOUDFRONT-*` family:

- [`SEC-AWS-CLOUDFRONT-001`](./SEC-AWS-CLOUDFRONT-001.md) — CloudFront distribution serves HTTP without redirect

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-CLOUDFRONT-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-CLOUDFRONT-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-CLOUDFRONT-002
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
