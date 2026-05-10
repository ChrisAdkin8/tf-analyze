---
title: "SEC-AWS-IAM-POLICY-006 — IAM policy uses `not_actions` or `not_resources`"
description: "tf-analyze rule SEC-AWS-IAM-POLICY-006 (MEDIUM · security): IAM policy uses `not_actions` or `not_resources`"
keywords: "security, medium, terraform, iac, aws, cis-1.16, mitre-T1078.004, cwe-269"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-IAM-POLICY-006 \u2014 IAM policy uses `not_actions` or `not_resources`",
  "description": "Rewrite the statement using `actions` and `resources` to enumerate\nthe explicit allow set. Reserve `not_actions` / `not_resources` for\nDeny statements (a defensive deny is safe to phrase negatively).",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-POLICY-006/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-POLICY-006/"
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
  "keywords": "security, medium, terraform, CIS 1.16, MITRE T1078.004, CWE-269",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-AWS-IAM-POLICY-006 — IAM policy uses `not_actions` or `not_resources`

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-IAM-POLICY-006" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-IAM-POLICY-006" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-IAM-POLICY-006 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **IAM policy uses `not_actions` or `not_resources`.** This rule has `default_urgency: MEDIUM` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`iam_policy_analysis`** — check: `not_action_or_not_resource` — _a `data "aws_iam_policy_document"` Allow statement matches the listed check._
  Statement uses `not_actions` or `not_resources` to express
"everything except X". Negative-form grants are notoriously
error-prone: any new AWS API or resource type added in future
is implicitly allowed. AWS itself recommends against negative
form for Allow statements.

## Why it likely fired

Statement uses `not_actions` or `not_resources` to express
"everything except X". Negative-form grants are notoriously
error-prone: any new AWS API or resource type added in future
is implicitly allowed. AWS itself recommends against negative
form for Allow statements.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-006` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Rewrite the statement using `actions` and `resources` to enumerate
the explicit allow set. Reserve `not_actions` / `not_resources` for
Deny statements (a defensive deny is safe to phrase negatively).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
data "aws_iam_policy_document" "example" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
```

## Verification

Policy statements with `Effect: Allow` should not contain `NotAction`
or `NotResource`.

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

**Source**
  - [`catalog/SEC-AWS-IAM-POLICY-006.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-POLICY-006.yaml) — canonical YAML

## Family

See also rules in the `SEC-AWS-IAM-POLICY-*` family:

- [`SEC-AWS-IAM-POLICY-001`](./SEC-AWS-IAM-POLICY-001.md) — IAM policy document grants wildcard `actions = [\"*\"]`
- [`SEC-AWS-IAM-POLICY-002`](./SEC-AWS-IAM-POLICY-002.md) — IAM policy document grants wildcard `iam:*` actions
- [`SEC-AWS-IAM-POLICY-003`](./SEC-AWS-IAM-POLICY-003.md) — IAM policy document grants wildcard `resources = [\"*\"]`
- [`SEC-AWS-IAM-POLICY-004`](./SEC-AWS-IAM-POLICY-004.md) — IAM policy document grants principal `identifiers = [\"*\"]` (public)
- [`SEC-AWS-IAM-POLICY-005`](./SEC-AWS-IAM-POLICY-005.md) — IAM policy grants both `actions = [\"*\"]` and `resources = [\"*\"]`

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-POLICY-006    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-POLICY-006` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-POLICY-006
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
