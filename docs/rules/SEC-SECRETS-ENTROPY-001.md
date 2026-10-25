---
title: "SEC-SECRETS-ENTROPY-001 — High-entropy string literal — probable hardcoded secret (API token / access key)"
description: "tf-analyze rule SEC-SECRETS-ENTROPY-001 (HIGH · security): High-entropy string literal — probable hardcoded secret (API token / access key)"
keywords: "security, high, terraform, iac, mitre-T1552.001, cwe-798, cwe-259"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-SECRETS-ENTROPY-001 \u2014 High-entropy string literal \u2014 probable hardcoded secret (API token / access key)",
  "description": "Never commit a literal secret. Source it from a secrets manager and\nreference it instead of inlining the value:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SECRETS-ENTROPY-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-SECRETS-ENTROPY-001/"
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
  "keywords": "security, high, terraform, MITRE T1552.001, CWE-798, CWE-259",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-SECRETS-ENTROPY-001 — High-entropy string literal — probable hardcoded secret (API token / access key)

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: infrastructure-wide](https://img.shields.io/badge/blast%20radius-infrastructure--wide-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-SECRETS-ENTROPY-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-SECRETS-ENTROPY-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-SECRETS-ENTROPY-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **High-entropy string literal — probable hardcoded secret (API token / access key).** This rule has `default_urgency: HIGH` and operates on a infrastructure wide blast radius. 

## What this checks

1. **`high_entropy_string`** — _a `high_entropy_string` pattern._
  A string literal whose Shannon entropy is >= 4.0 bits/char over a
base64/token charset (length 20-100), assigned to *any* argument —
the signature of a hardcoded API token, access key, or other secret
regardless of the argument's name. Complements the name-based grep
secret rules (SEC-SECRETS-001), which only fire on
`password`/`secret`/`api_key`-style fields and miss a token dropped
into an oddly-named argument. Interpolations (`var.*`, `${...}`),
cloud resource-ids (`ami-...`), and hex / git-SHA-class strings
(entropy < 4.0) are excluded to keep false positives low. This is a
heuristic — verify and rotate the value if it is a real credential.

## Why it likely fired

A string literal whose Shannon entropy is >= 4.0 bits/char over a
base64/token charset (length 20-100), assigned to *any* argument —
the signature of a hardcoded API token, access key, or other secret
regardless of the argument's name. Complements the name-based grep
secret rules (SEC-SECRETS-001), which only fire on
`password`/`secret`/`api_key`-style fields and miss a token dropped
into an oddly-named argument. Interpolations (`var.*`, `${...}`),
cloud resource-ids (`ami-...`), and hex / git-SHA-class strings
(entropy < 4.0) are excluded to keep false positives low. This is a
heuristic — verify and rotate the value if it is a real credential.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-SECRETS-ENTROPY-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Never commit a literal secret. Source it from a secrets manager and
reference it instead of inlining the value:

    data "aws_secretsmanager_secret_version" "db" {
      secret_id = "prod/db/password"
    }

    resource "aws_db_instance" "db" {
      password = data.aws_secretsmanager_secret_version.db.secret_string
    }

If the flagged value is genuinely not a secret (e.g. an opaque public
identifier), suppress it at the line with a reason:
`# tf-analyze:ignore SEC-SECRETS-ENTROPY-001 -- <why this is not a secret>`.

CWE-798 (Use of Hard-coded Credentials) / CWE-259 (Hard-coded Password).

## Verification

Confirm the flagged value is not a live credential. If it is, treat it as
compromised — it is in git history — rotate it immediately and move it to a
secrets manager. `git log -p -S '<value>'` shows when it was introduced.

## References

**MITRE ATT&CK**
  - [`T1552.001`](https://attack.mitre.org/techniques/T1552/001/)

**CWE**
  - [`CWE-798`](https://cwe.mitre.org/data/definitions/798.html)
  - [`CWE-259`](https://cwe.mitre.org/data/definitions/259.html)

**Source**
  - [`catalog/SEC-SECRETS-ENTROPY-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-SECRETS-ENTROPY-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-SECRETS-ENTROPY-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-SECRETS-ENTROPY-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-SECRETS-ENTROPY-001
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
