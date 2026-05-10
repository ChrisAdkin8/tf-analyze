---
title: "MOD-PIN-001 — Module source not pinned"
description: "tf-analyze rule MOD-PIN-001 (HIGH · module): Module source not pinned"
keywords: "module, high, terraform, iac, mitre-T1195.002, cwe-1357, d3-sca"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-PIN-001 \u2014 Module source not pinned",
  "description": "Pin every external module:\n - Registry: add `version = \"~> X.Y\"`.\n - Git: add `?ref=v1.2.3` or `?ref=<commit-sha>` to the source URL.\n - Local (`./modules/foo`): no pin needed but verify the path is stable.",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-PIN-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-PIN-001/"
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
  "keywords": "module, high, terraform, MITRE T1195.002, CWE-1357, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "module",
  "isAccessibleForFree": true
}
</script>

# ⚠️ MOD-PIN-001 — Module source not pinned

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: module](https://img.shields.io/badge/section-module-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-PIN-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-PIN-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-PIN-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Module source not pinned.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"git::[^"]*"\s*$/` — _a textual regex matched somewhere in the file._
  git source without ?ref= pin
2. **`grep`** matching `/source\s*=\s*"github\.com/[^"]*"\s*$/` — _a textual regex matched somewhere in the file._
  github.com source without ?ref= pin
3. **`grep`** matching `/source\s*=\s*"bitbucket\.org/[^"]*"\s*$/` — _a textual regex matched somewhere in the file._
  bitbucket.org source without ?ref= pin
4. **`module_block_missing_arg`** (`version`) — _a `module_block_missing_arg` pattern._
  registry source without version constraint

## Why it likely fired

git source without ?ref= pin

github.com source without ?ref= pin

bitbucket.org source without ?ref= pin

registry source without version constraint

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-PIN-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pin every external module:
 - Registry: add `version = "~> X.Y"`.
 - Git: add `?ref=v1.2.3` or `?ref=<commit-sha>` to the source URL.
 - Local (`./modules/foo`): no pin needed but verify the path is stable.

## Suggested fix (`fix_hcl`)

![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)

```hcl
module "example" {
  source  = "hashicorp/consul/aws"
  version = "= 0.11.0"
}
```

## Verification

Run `terraform get -update` and confirm the same version resolves on
every machine. Commit `.terraform.lock.hcl`.

## References

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Open Source Dependency Scanning`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**Source**
  - [`catalog/MOD-PIN-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-PIN-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-PIN-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-PIN-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-PIN-001
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
