---
title: "SEC-AWS-IAM-002 — IAM assume role policy with wildcard Principal"
description: "tf-analyze rule SEC-AWS-IAM-002 (CRITICAL · security): IAM assume role policy with wildcard Principal"
keywords: "security, critical, terraform, iac, aws, cis-1.16, mitre-T1078.004, cwe-269, cwe-732, d3-pa, d3-mfa, nist-csf-pr.ac-1, nist-csf-pr.ac-4, nist-800-53-ac-3, nist-800-53-ac-6, csa-ccm-iam-09"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-IAM-002 \u2014 IAM assume role policy with wildcard Principal",
  "description": "Restrict the `Principal` in assume role policies to specific AWS account\nIDs, IAM roles, or services. A wildcard principal (`\"Principal\": \"*\"`)\nallows any entity in the world to call `sts:AssumeRole`, effectively\nmaking the role public unle",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-002/"
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
  "keywords": "security, critical, terraform, CIS 1.16, MITRE T1078.004, CWE-269, CWE-732, D3-PA, D3-MFA",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-AWS-IAM-002 — IAM assume role policy with wildcard Principal

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-IAM-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-IAM-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-IAM-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **IAM assume role policy with wildcard Principal.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/"Principal"\s*:\s*"\*"/` — _a textual regex matched somewhere in the file._
  IAM assume role policy with Principal = "*"
2. **`grep`** matching `/principals\s*\{[^}]*type\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
  aws_iam_role inline principals block with type = "*"
3. **`grep`** matching `/Principal\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
  IAM assume role policy Principal = "*" in jsonencode HCL object syntax

## Why it likely fired

IAM assume role policy with Principal = "*"

aws_iam_role inline principals block with type = "*"

IAM assume role policy Principal = "*" in jsonencode HCL object syntax

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Restrict the `Principal` in assume role policies to specific AWS account
IDs, IAM roles, or services. A wildcard principal (`"Principal": "*"`)
allows any entity in the world to call `sts:AssumeRole`, effectively
making the role public unless a restrictive Condition is also present.
Replace `"Principal": "*"` with the exact ARN(s) of the trusted entity,
e.g. `"Principal": {"Service": "lambda.amazonaws.com"}` or
`"Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"}`.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
resource "aws_iam_role" "example" {
  name = "example"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
```

## Verification

Run `aws iam get-role --role-name <name>` and inspect the
`AssumeRolePolicyDocument`. Confirm there is no `"Principal": "*"`
without a restrictive `Condition` block. Run `terraform plan` and
verify the rendered policy document in the plan output has no
wildcard principal.

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
  - [`catalog/SEC-AWS-IAM-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-IAM-*` family:

- [`SEC-AWS-IAM-001`](./SEC-AWS-IAM-001.md) — IAM policy with wildcard resource
- [`SEC-AWS-IAM-003`](./SEC-AWS-IAM-003.md) — IAM account password policy is not configured or too weak

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-002
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
