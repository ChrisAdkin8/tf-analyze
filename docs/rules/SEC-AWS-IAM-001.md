---
title: "SEC-AWS-IAM-001 — IAM policy with wildcard resource"
description: "tf-analyze rule SEC-AWS-IAM-001 (HIGH · security): IAM policy with wildcard resource"
keywords: "security, high, terraform, iac, aws, cis-1.16, mitre-T1078.004, cwe-269, cwe-732, d3-pa, d3-mfa, nist-csf-pr.ac-1, nist-csf-pr.ac-4, nist-800-53-ac-3, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-IAM-001 \u2014 IAM policy with wildcard resource",
  "description": "Narrow the `Resource` field to the specific ARN(s) the policy needs.\nWildcard resources grant the actions to every resource in the account,\nviolating least-privilege. Use `arn:aws:s3:::my-bucket/*` instead of\n`*` for S3 access, `arn:aws:dyn",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-001/"
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
  "keywords": "security, high, terraform, CIS 1.16, MITRE T1078.004, CWE-269, CWE-732, D3-PA, D3-MFA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AWS-IAM-001 — IAM policy with wildcard resource

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-IAM-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-IAM-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-IAM-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **IAM policy with wildcard resource.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/"Resource"\s*:\s*"\*"/` — _a textual regex matched somewhere in the file._
  IAM policy document with Resource = "*"
2. **`grep`** matching `/resources\s*=\s*\["\*"\]/` — _a textual regex matched somewhere in the file._
  aws_iam_policy_document statement with resources = ["*"]

## Why it likely fired

IAM policy document with Resource = "*"

aws_iam_policy_document statement with resources = ["*"]

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Narrow the `Resource` field to the specific ARN(s) the policy needs.
Wildcard resources grant the actions to every resource in the account,
violating least-privilege. Use `arn:aws:s3:::my-bucket/*` instead of
`*` for S3 access, `arn:aws:dynamodb:*:*:table/my-table` for DynamoDB,
etc.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
statement {
  actions   = ["s3:GetObject", "s3:PutObject"]
  resources = ["arn:aws:s3:::my-bucket/*"]
}
```

_Narrowing the resource ARN is an in-place policy update; no replacement is required but IAM propagation may take up to 60 seconds._

## Verification

Run `terraform plan` and verify the policy document in the plan output
has no `"Resource": "*"` statements.

## References

**CIS Benchmark**
  - `CIS 1.16`

**PCI-DSS**
  - `Req-7.1`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Resource Permission Minimization`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)

**MITRE D3FEND**
  - [`D3-PA`](https://d3fend.mitre.org/technique/D3-PA/)
  - [`D3-MFA`](https://d3fend.mitre.org/technique/D3-MFA/)

**NIST CSF 2.0**
  - [`PR.AC-1`](https://www.nist.gov/cyberframework)
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-IAM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-IAM-*` family:

- [`SEC-AWS-IAM-002`](./SEC-AWS-IAM-002.md) — IAM assume role policy with wildcard Principal
- [`SEC-AWS-IAM-003`](./SEC-AWS-IAM-003.md) — IAM account password policy is not configured or too weak

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-001
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
