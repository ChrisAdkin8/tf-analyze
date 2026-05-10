---
title: "SEC-CICD-003 — Apply job missing `environment:` with required_reviewers for production"
description: "tf-analyze rule SEC-CICD-003 (CRITICAL · cicd): Apply job missing `environment:` with required_reviewers for production"
keywords: "cicd, critical, terraform, iac, mitre-T1199, cwe-732, cwe-862"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-CICD-003 \u2014 Apply job missing `environment:` with required_reviewers for production",
  "description": "Pair every auto-approve apply with an `environment:` block on the\njob:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-CICD-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-CICD-003/"
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
  "keywords": "cicd, critical, terraform, MITRE T1199, CWE-732, CWE-862",
  "proficiencyLevel": "Expert",
  "articleSection": "cicd",
  "isAccessibleForFree": true
}
</script>

# 🚨 SEC-CICD-003 — Apply job missing `environment:` with required_reviewers for production

![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square) ![Section: cicd](https://img.shields.io/badge/section-cicd-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square) ![Status: stub](https://img.shields.io/badge/status-stub-grey?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-CICD-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-CICD-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-CICD-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Apply job missing `environment:` with required_reviewers for production.** This rule has `default_urgency: CRITICAL` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`grep`** matching `/terraform\s+(apply|destroy)\s+(?:-auto-approve|.*plan\.binary)/` — _a textual regex matched somewhere in the file._
  `terraform apply -auto-approve` (or `apply tfplan.binary`) in a
workflow that does NOT also declare an `environment:` block
means the job can run on a forked-PR fork-bomb or a compromised
branch protection bypass without any human-in-the-loop gate.
SLSA L3 + NIST SSDF PO.4 both require this gate for change
approval; OWASP CICD-SEC-1/-7 enumerate it as the canonical
Insufficient Flow Control example.

## Why it likely fired

`terraform apply -auto-approve` (or `apply tfplan.binary`) in a
workflow that does NOT also declare an `environment:` block
means the job can run on a forked-PR fork-bomb or a compromised
branch protection bypass without any human-in-the-loop gate.
SLSA L3 + NIST SSDF PO.4 both require this gate for change
approval; OWASP CICD-SEC-1/-7 enumerate it as the canonical
Insufficient Flow Control example.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-CICD-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pair every auto-approve apply with an `environment:` block on the
job:

    jobs:
      apply:
        if: github.ref == 'refs/heads/main'
        environment:
          name: production
        steps:
          - run: terraform apply -auto-approve tfplan.binary

Configure the protected environment with `required_reviewers` and a
wait timer in repository settings. Without this, a compromised
workflow file pushed to `main` reaches production with zero review.

## Verification

Open every workflow that runs `terraform apply` and confirm an
`environment:` block is present. Cross-check repository
Settings → Environments → production for required reviewers.

## References

**MITRE ATT&CK**
  - [`T1199`](https://attack.mitre.org/techniques/T1199/)

**CWE**
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)
  - [`CWE-862`](https://cwe.mitre.org/data/definitions/862.html)

**Source**
  - [`catalog/SEC-CICD-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-CICD-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-CICD-*` family:

- [`SEC-CICD-001`](./SEC-CICD-001.md) — Workflow file applies Terraform without required-reviewers gate
- [`SEC-CICD-002`](./SEC-CICD-002.md) — Workflow uses `permissions: write-all` or omits minimum scopes

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-CICD-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-CICD-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-CICD-003
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
