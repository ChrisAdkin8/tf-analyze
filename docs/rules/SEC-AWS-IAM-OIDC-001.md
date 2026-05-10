---
title: "SEC-AWS-IAM-OIDC-001 — GitHub OIDC trust policy accepts wildcard `repo:*` or `sub: *` claims"
description: "tf-analyze rule SEC-AWS-IAM-OIDC-001 (CRITICAL · security): GitHub OIDC trust policy accepts wildcard `repo:*` or `sub: *` claims"
keywords: "security, critical, terraform, iac, aws, mitre-T1199, mitre-T1078.004, cwe-287, cwe-862"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AWS-IAM-OIDC-001 \u2014 GitHub OIDC trust policy accepts wildcard `repo:*` or `sub: *` claims",
  "description": "Pin the `sub` claim to the exact repo + branch (or environment)\nthat needs the role:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-OIDC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AWS-IAM-OIDC-001/"
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
  "keywords": "security, critical, terraform, MITRE T1199, MITRE T1078.004, CWE-287, CWE-862",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-AWS-IAM-OIDC-001 — GitHub OIDC trust policy accepts wildcard `repo:*` or `sub: *` claims

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AWS-IAM-OIDC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-AWS-IAM-OIDC-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-AWS-IAM-OIDC-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **GitHub OIDC trust policy accepts wildcard `repo:*` or `sub: *` claims.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/"token\.actions\.githubusercontent\.com:sub"\s*=\s*"(?:\*|repo:\*|repo:[^"/]+/\*|repo:[^"]*:ref:refs/heads/\*)"/` — _a textual regex matched somewhere in the file._
  A GitHub OIDC IAM-role trust policy whose `sub` claim is
`repo:*`, `repo:<org>/*`, or `:ref:refs/heads/*` lets any
workflow in the matching scope assume the role. The 2024
Microsoft VS Code OIDC mishap and the Codecov 2021 compromise
both turned on this pattern — a less-trusted repo or branch
gets to mint cloud credentials.
2. **`grep`** matching `/"token\.actions\.githubusercontent\.com:sub"\s*=\s*"\*"/` — _a textual regex matched somewhere in the file._
  bare wildcard `sub`

## Why it likely fired

A GitHub OIDC IAM-role trust policy whose `sub` claim is
`repo:*`, `repo:<org>/*`, or `:ref:refs/heads/*` lets any
workflow in the matching scope assume the role. The 2024
Microsoft VS Code OIDC mishap and the Codecov 2021 compromise
both turned on this pattern — a less-trusted repo or branch
gets to mint cloud credentials.

bare wildcard `sub`

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AWS-IAM-OIDC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pin the `sub` claim to the exact repo + branch (or environment)
that needs the role:

    "token.actions.githubusercontent.com:sub" =
      "repo:my-org/infra:ref:refs/heads/main"

Or pin to a protected environment:

    "token.actions.githubusercontent.com:sub" =
      "repo:my-org/infra:environment:production"

For multi-repo orgs use `StringLike` with explicit repo names
rather than a wildcard org match. Combine with the audience claim
(`token.actions.githubusercontent.com:aud = "sts.amazonaws.com"`)
for defence in depth.

## Verification

Query IAM for every role trust policy:

    aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument]' \
      | jq '.[] | select(.AssumeRolePolicyDocument | tostring | contains("token.actions.githubusercontent.com"))'

Confirm no `sub` value is `*`, `repo:*`, or ends in `:ref:refs/heads/*`.

## References

**MITRE ATT&CK**
  - [`T1199`](https://attack.mitre.org/techniques/T1199/)
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-287`](https://cwe.mitre.org/data/definitions/287.html)
  - [`CWE-862`](https://cwe.mitre.org/data/definitions/862.html)

**Source**
  - [`catalog/SEC-AWS-IAM-OIDC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AWS-IAM-OIDC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AWS-IAM-OIDC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AWS-IAM-OIDC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AWS-IAM-OIDC-001
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
