---
title: "SEC-AWS-IAM-JSON-003 — Inline IAM policy JSON grants `Action: \\"*\\"` AND `Resource: \\"*\\"`"
description: "tf-analyze rule SEC-AWS-IAM-JSON-003 (CRITICAL · security): Inline IAM policy JSON grants `Action: \'*\'` AND `Resource: \'*\'`"
keywords: "security, critical, terraform, iac, aws, cis-1.16, mitre-T1078.004, mitre-T1098.001, cwe-269, cwe-732"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-IAM-JSON-003 \u2014 Inline IAM policy JSON grants `Action: \\\"*\\\"` AND `Resource: \\\"*\\\"`",
  "description": "If true administrator access is intended, attach\n`arn:aws:iam::aws:policy/AdministratorAccess` directly via\n`aws_iam_role_policy_attachment`. Otherwise, scope to the explicit\nminimum action and resource set.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-JSON-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-JSON-003/"
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
  "keywords": "security, critical, terraform, CIS 1.16, MITRE T1078.004, MITRE T1098.001, CWE-269, CWE-732",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-AWS-IAM-JSON-003 — Inline IAM policy JSON grants `Action: \"*\"` AND `Resource: \"*\"`

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-IAM-JSON-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-IAM-JSON-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-IAM-JSON-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Inline IAM policy JSON grants `Action: \"*\"` AND `Resource: \"*\"`.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_json_policy_analysis`** — check: `wildcard_action_and_resource` — _an inline `policy = jsonencode({...})` Allow statement matches the listed check._
  Inline JSON policy contains a single Allow statement granting
both `Action: "*"` and `Resource: "*"` — the canonical
AdministratorAccess shape, hand-rolled inline rather than via
the named AWS-managed policy. Bypasses org-level controls and
audit tools that recognise `AdministratorAccess`.

## Why it likely fired

Inline JSON policy contains a single Allow statement granting
both `Action: "*"` and `Resource: "*"` — the canonical
AdministratorAccess shape, hand-rolled inline rather than via
the named AWS-managed policy. Bypasses org-level controls and
audit tools that recognise `AdministratorAccess`.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

If true administrator access is intended, attach
`arn:aws:iam::aws:policy/AdministratorAccess` directly via
`aws_iam_role_policy_attachment`. Otherwise, scope to the explicit
minimum action and resource set.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "aws_iam_policy" "example" {
  name   = "example"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:GetObject", "s3:PutObject"],
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}
```

## Verification

No statement in the rendered policy may combine `Action: "*"` and
`Resource: "*"`. CloudTrail data events on this principal should
narrow to a small set of services after the fix.

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
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)

**Source**
  - [`catalog/SEC-AWS-IAM-JSON-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-JSON-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-IAM-JSON-*` family:

- [`SEC-AWS-IAM-JSON-001`](./SEC-AWS-IAM-JSON-001.md) — Inline IAM policy JSON grants wildcard `Action: \"*\"`
- [`SEC-AWS-IAM-JSON-002`](./SEC-AWS-IAM-JSON-002.md) — Inline IAM policy JSON grants wildcard `iam:*` action
- [`SEC-AWS-IAM-JSON-004`](./SEC-AWS-IAM-JSON-004.md) — Inline IAM policy JSON has public principal (`Principal: \"*\"`)

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-JSON-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-JSON-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-JSON-003
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
