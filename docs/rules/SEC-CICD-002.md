---
title: "SEC-CICD-002 — Workflow uses `permissions: write-all` or omits minimum scopes"
description: "tf-analyze rule SEC-CICD-002 (HIGH · cicd): Workflow uses `permissions: write-all` or omits minimum scopes"
keywords: "cicd, high, terraform, iac, mitre-T1078.004, mitre-T1098.001, cwe-269, cwe-250"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-CICD-002 \u2014 Workflow uses `permissions: write-all` or omits minimum scopes",
  "description": "Replace blanket scopes with explicit minimums:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-CICD-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-CICD-002/"
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
  "keywords": "cicd, high, terraform, MITRE T1078.004, MITRE T1098.001, CWE-269, CWE-250",
  "proficiencyLevel": "Expert",
  "articleSection": "cicd",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-CICD-002 — Workflow uses `permissions: write-all` or omits minimum scopes

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: cicd](https://img.shields.io/badge/section-cicd-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square) ![Status: stub](https://img.shields.io/badge/status-stub-grey?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-CICD-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-CICD-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-CICD-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Workflow uses `permissions: write-all` or omits minimum scopes.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/permissions\s*:\s*write-all/` — _a textual regex matched somewhere in the file._
  `permissions: write-all` grants the runner's GITHUB_TOKEN every
scope. A workflow that only needs `contents: read` and
`id-token: write` should declare exactly that. The blanket form
is what gives a compromised dependency the keys to your registry.

## Why it likely fired

`permissions: write-all` grants the runner's GITHUB_TOKEN every
scope. A workflow that only needs `contents: read` and
`id-token: write` should declare exactly that. The blanket form
is what gives a compromised dependency the keys to your registry.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-CICD-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace blanket scopes with explicit minimums:

    permissions:
      contents: read
      id-token: write   # only if exchanging for OIDC
      pull-requests: write  # only if commenting on PRs

SLSA L2 (Provenance) and OWASP CICD-SEC-1 (Insufficient Flow Control
Mechanisms) both require declared minimum scopes; the default
permissions for new repos are `read` only, so most workflows can
drop the block entirely.

## Verification

```sh
`grep -rn "permissions:" .github/workflows/`. Confirm no workflow
uses `write-all` and that every `terraform apply` workflow declares
`id-token: write` plus the specific writes it needs.
```

## References

**MITRE ATT&CK**
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)
  - [`T1098.001`](https://attack.mitre.org/techniques/T1098/001/)

**CWE**
  - [`CWE-269`](https://cwe.mitre.org/data/definitions/269.html)
  - [`CWE-250`](https://cwe.mitre.org/data/definitions/250.html)

**Source**
  - [`catalog/SEC-CICD-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-CICD-002.yaml) — canonical YAML

## Family

See also rules in the `SEC-CICD-*` family:

- [`SEC-CICD-001`](./SEC-CICD-001.md) — Workflow file applies Terraform without required-reviewers gate
- [`SEC-CICD-003`](./SEC-CICD-003.md) — Apply job missing `environment:` with required_reviewers for production

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-CICD-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-CICD-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-CICD-002
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
