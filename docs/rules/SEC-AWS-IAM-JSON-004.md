---
title: "SEC-AWS-IAM-JSON-004 — Inline IAM policy JSON has public principal (`Principal: \\"*\\"`)"
description: "tf-analyze rule SEC-AWS-IAM-JSON-004 (CRITICAL · security): Inline IAM policy JSON has public principal (`Principal: \'*\'`)"
keywords: "security, critical, terraform, iac, aws, cis-1.16, mitre-T1078.004, cwe-269, nist-csf-pr.ac-4, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-IAM-JSON-004 \u2014 Inline IAM policy JSON has public principal (`Principal: \\\"*\\\"`)",
  "description": "Replace the wildcard principal with the specific account or role\nARNs that should have access. If true public exposure is the\nintent, gate it behind explicit `Condition` keys and a documented\nexception in your security review process.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-JSON-004/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-JSON-004/"
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
  "keywords": "security, critical, terraform, CIS 1.16, MITRE T1078.004, CWE-269",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-AWS-IAM-JSON-004 — Inline IAM policy JSON has public principal (`Principal: \"*\"`)

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-IAM-JSON-004" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-IAM-JSON-004" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-IAM-JSON-004 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Inline IAM policy JSON has public principal (`Principal: \"*\"`).** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_json_policy_analysis`** — check: `public_principal` — _an inline `policy = jsonencode({...})` Allow statement matches the listed check._
  Inline JSON policy includes an Allow statement whose `Principal`
is `"*"` (or any sub-key whose value contains `"*"`). This makes
whatever resource the policy attaches to public — every account
on the planet plus AWS service principals can invoke the
granted actions.

## Why it likely fired

Inline JSON policy includes an Allow statement whose `Principal`
is `"*"` (or any sub-key whose value contains `"*"`). This makes
whatever resource the policy attaches to public — every account
on the planet plus AWS service principals can invoke the
granted actions.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-004` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace the wildcard principal with the specific account or role
ARNs that should have access. If true public exposure is the
intent, gate it behind explicit `Condition` keys and a documented
exception in your security review process.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_iam_role_policy" "example" {
  name = "example"
  role = aws_iam_role.target.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Action    = "sts:AssumeRole",
        Resource  = "*",
        Principal = { AWS = ["arn:aws:iam::123456789012:root"] }
      }
    ]
  })
}
```

## Verification

The policy's `Principal` field must be a structured object listing
AWS account IDs or service principals, not `"*"`.

## References

**CIS Benchmark**
  - `CIS 1.16`

**PCI-DSS**
  - `Req-7.2.2`

**SOC 2 Trust Services Criteria**
  - `CC6.1`

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Resource Permission Minimization`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**Source**
  - [`catalog/SEC-AWS-IAM-JSON-004.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-JSON-004.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-IAM-JSON-*` family:

- [`SEC-AWS-IAM-JSON-001`](./SEC-AWS-IAM-JSON-001.md) — Inline IAM policy JSON grants wildcard `Action: \"*\"`
- [`SEC-AWS-IAM-JSON-002`](./SEC-AWS-IAM-JSON-002.md) — Inline IAM policy JSON grants wildcard `iam:*` action
- [`SEC-AWS-IAM-JSON-003`](./SEC-AWS-IAM-JSON-003.md) — Inline IAM policy JSON grants `Action: \"*\"` AND `Resource: \"*\"`

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-004    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-JSON-004` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-JSON-004
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
