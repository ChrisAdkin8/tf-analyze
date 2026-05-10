---
title: "SEC-SUPPLY-001 — Module source not pinned to an immutable digest or signed tag"
description: "tf-analyze rule SEC-SUPPLY-001 (HIGH · security): Module source not pinned to an immutable digest or signed tag"
keywords: "security, high, terraform, iac, mitre-T1195.001, mitre-T1195.002, cwe-1357"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-SUPPLY-001 \u2014 Module source not pinned to an immutable digest or signed tag",
  "description": "Replace mutable refs with a content-addressed pin:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SUPPLY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SUPPLY-001/"
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
  "keywords": "security, high, terraform, MITRE T1195.001, MITRE T1195.002, CWE-1357",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-SUPPLY-001 — Module source not pinned to an immutable digest or signed tag

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-SUPPLY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-SUPPLY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-SUPPLY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module source not pinned to an immutable digest or signed tag.** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`module_block_missing_arg`** (`ref`) — _a `module_block_missing_arg` pattern._
  Git source without a ref= pin lands on the default branch (`HEAD`).
Without a commit SHA or signed tag the module body can change under
you between plans — supply-chain compromise of the upstream repo
reaches every consumer at the next `terraform init`. Pin to a
40-char commit SHA, a verified tag, or a content digest.

## Why it likely fired

Git source without a ref= pin lands on the default branch (`HEAD`).
Without a commit SHA or signed tag the module body can change under
you between plans — supply-chain compromise of the upstream repo
reaches every consumer at the next `terraform init`. Pin to a
40-char commit SHA, a verified tag, or a content digest.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SUPPLY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Replace mutable refs with a content-addressed pin:

* **Git over HTTPS/SSH** — use `?ref=<40-char-commit-SHA>` rather than
  `?ref=main` or unversioned. Signed tags via `?ref=v1.2.3` are
  acceptable when paired with `terraform init -backend-verify-tag`.
* **Terraform Registry** — always set `version = "= X.Y.Z"` (or a
  tight range; never `>=` alone).
* **GitHub Actions, when consumed from Terraform via `data "external"` —
  pin to a SHA, not a tag. Tags are mutable on GitHub.

Pinning is the cheapest hardening against the 2024 GitHub Actions
tj-actions/changed-files attack — the same risk applies to any
source mounted via `source = "github.com/..."`.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
module "vpc" {
  # 40-char SHA pin — module body is content-addressed
  source = "github.com/terraform-aws-modules/terraform-aws-vpc?ref=4f3d8b6c9a2e1f70d8b4c6e2a1f93d7c0b5e8f44"
  name   = "primary"
}
```

_Pinning to a new SHA may surface latent compatibility issues that
the previous mutable ref was masking. Review `terraform plan` after
re-init._

## Verification

Run `grep -rE 'source\s*=\s*"github\.com|git::' .` and confirm
every match carries a `?ref=` query string with a 40-char hex SHA
or a verified release tag. Re-running tf-analyze should report zero
SEC-SUPPLY-001 findings.

## References

**MITRE ATT&CK**
  - [`T1195.001`](https://attack.mitre.org/techniques/T1195/001/)
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)

**Source**
  - [`catalog/SEC-SUPPLY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SUPPLY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SUPPLY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SUPPLY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SUPPLY-001
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
