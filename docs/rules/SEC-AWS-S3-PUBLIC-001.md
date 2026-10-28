---
title: "SEC-AWS-S3-PUBLIC-001 — S3 bucket ACL grants access to everyone"
description: "tf-analyze rule SEC-AWS-S3-PUBLIC-001 (HIGH · security): S3 bucket ACL grants access to everyone"
keywords: "security, high, terraform, iac, aws, cis-2.1.5.1, mitre-T1530, cwe-732, cwe-284, nist-csf-pr.ac-3, nist-csf-pr.ac-4, nist-800-53-ac-3, nist-800-53-ac-6, csa-ccm-iam-09, csa-ccm-dsp-17"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-S3-PUBLIC-001 \u2014 S3 bucket ACL grants access to everyone",
  "description": "Keep bucket ACLs private and grant access through IAM or a bucket\npolicy that names specific principals. `public-read` and\n`public-read-write` let anyone on the internet list or change the\nobjects; `authenticated-read` and the `Authenticate",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-S3-PUBLIC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-S3-PUBLIC-001/"
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
  "keywords": "security, high, terraform, CIS 2.1.5.1, MITRE T1530, CWE-732, CWE-284",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-S3-PUBLIC-001 — S3 bucket ACL grants access to everyone

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-S3-PUBLIC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-S3-PUBLIC-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-S3-PUBLIC-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **S3 bucket ACL grants access to everyone.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `aws_s3_bucket_acl` (`acl`) matching `/^(public-read|public-read-write|authenticated-read)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `aws_s3_bucket_acl` with a canned ACL that grants everyone (or every AWS account) access
2. **`resource_arg`** on `aws_s3_bucket` (`acl`) matching `/^(public-read|public-read-write|authenticated-read)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  legacy inline `acl` on `aws_s3_bucket` (pre-v4 provider)
3. **`resource_arg`** on `aws_s3_bucket_acl` (`access_control_policy.grant.grantee.uri`) matching `/acs\.amazonaws\.com/groups/global/(AllUsers|AuthenticatedUsers)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `access_control_policy` grant to the AllUsers or AuthenticatedUsers group
4. **`resource_arg`** on `aws_s3_bucket` (`grant.uri`) matching `/acs\.amazonaws\.com/groups/global/(AllUsers|AuthenticatedUsers)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  legacy inline `grant` to the AllUsers or AuthenticatedUsers group

## Why it likely fired

`aws_s3_bucket_acl` with a canned ACL that grants everyone (or every AWS account) access

legacy inline `acl` on `aws_s3_bucket` (pre-v4 provider)

`access_control_policy` grant to the AllUsers or AuthenticatedUsers group

legacy inline `grant` to the AllUsers or AuthenticatedUsers group

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-S3-PUBLIC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Keep bucket ACLs private and grant access through IAM or a bucket
policy that names specific principals. `public-read` and
`public-read-write` let anyone on the internet list or change the
objects; `authenticated-read` and the `AuthenticatedUsers` group mean
any AWS account at all, not just yours.

Better still, turn ACLs off: set `object_ownership = "BucketOwnerEnforced"`
on `aws_s3_bucket_ownership_controls` and add an
`aws_s3_bucket_public_access_block` with all four flags `true`. For a
public website, serve the bucket through CloudFront with origin access
control instead of making it public.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_s3_bucket_ownership_controls" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
```

_Disabling ACLs removes every ACL grant on the bucket and its objects; clients relying on a public or cross-account ACL lose access._

## Verification

```sh
`aws s3api get-bucket-acl --bucket <name>` must show no grant to
`http://acs.amazonaws.com/groups/global/AllUsers` or
`.../AuthenticatedUsers`.
```

## References

**CIS Benchmark**
  - `CIS 2.1.5.1`

**MITRE ATT&CK**
  - [`T1530`](https://attack.mitre.org/techniques/T1530/)

**CWE**
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)
  - [`CWE-284`](https://cwe.mitre.org/data/definitions/284.html)

**NIST CSF 2.0**
  - [`PR.AC-3`](https://www.nist.gov/cyberframework)
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`DSP-17`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-S3-PUBLIC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-S3-PUBLIC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-S3-PUBLIC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-S3-PUBLIC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-S3-PUBLIC-001
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
