---
title: "SEC-AWS-ACCESSKEY-001 — Long-lived IAM access key created for a user"
description: "tf-analyze rule SEC-AWS-ACCESSKEY-001 (HIGH · security): Long-lived IAM access key created for a user"
keywords: "security, high, terraform, iac, aws, cis-1.14, nist-csf-pr.ac-1, nist-csf-pr.ac-6, nist-800-53-ia-5, csa-ccm-iam-04"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-ACCESSKEY-001 \u2014 Long-lived IAM access key created for a user",
  "description": "Avoid long-lived IAM access keys entirely. Use IAM roles with temporary\ncredentials instead:\n- EC2 workloads: EC2 instance profiles\n- Lambda: Lambda execution roles\n- CI/CD: OIDC federation (GitHub Actions, GitLab CI, CircleCI, etc.)\n- Cros",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ACCESSKEY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-ACCESSKEY-001/"
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
  "keywords": "security, high, terraform, CIS 1.14",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-ACCESSKEY-001 — Long-lived IAM access key created for a user

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-ACCESSKEY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-ACCESSKEY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-ACCESSKEY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Long-lived IAM access key created for a user.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`resource_present`** on `aws_iam_access_key` — _this resource type exists in the corpus and is itself a finding._
  Long-lived IAM access key resource present in Terraform configuration

## Why it likely fired

Long-lived IAM access key resource present in Terraform configuration

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-ACCESSKEY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Avoid long-lived IAM access keys entirely. Use IAM roles with temporary
credentials instead:
- EC2 workloads: EC2 instance profiles
- Lambda: Lambda execution roles
- CI/CD: OIDC federation (GitHub Actions, GitLab CI, CircleCI, etc.)
- Cross-account: `sts:AssumeRole`

If a long-lived key is truly unavoidable (a legacy system that cannot
use OIDC), enforce these mitigations:
1. Rotate every 90 days via automation.
2. Store the secret in AWS Secrets Manager or HashiCorp Vault — never
   in `terraform.tfvars` or CI/CD environment variables in plaintext.
3. Attach a policy that restricts the key to the minimum required actions
   and resources.
4. Enable CloudTrail and alert on unusual usage patterns.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
# Replace long-lived access key with an IAM instance profile (EC2 example)
resource "aws_iam_role" "app" {
  name = "app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "app"
  role = aws_iam_role.app.name
}
# Remove the aws_iam_access_key resource entirely
```

## Verification

Run `aws iam list-access-keys --user-name <name>` and confirm no keys
exist, or that existing keys were created within the last 90 days.
Search the codebase for `aws_iam_access_key` resources and ensure
removal is tracked in a migration plan.

## References

**CIS Benchmark**
  - `CIS 1.14`

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)
  - [`PR.AC-6`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`IA-5`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ia-5)

**CSA CCM v4**
  - [`IAM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-ACCESSKEY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-ACCESSKEY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-ACCESSKEY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-ACCESSKEY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-ACCESSKEY-001
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
