---
title: "STK-GCP-DNS-002 — Cloud DNS DNSSEC uses deprecated RSASHA1 algorithm"
description: "tf-analyze rule STK-GCP-DNS-002 (LOW · stack): Cloud DNS DNSSEC uses deprecated RSASHA1 algorithm"
keywords: "stack, low, terraform, iac, gcp, cis-3.4, mitre-T1583.002, cwe-327, d3-et, nist-csf-pr.ds-2, nist-800-53-sc-13"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-GCP-DNS-002 \u2014 Cloud DNS DNSSEC uses deprecated RSASHA1 algorithm",
  "description": "Use a NIST-approved algorithm (`rsasha256`, `ecdsap256sha256`, or\n`ecdsap384sha384`):",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DNS-002/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-GCP-DNS-002/"
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
  "keywords": "stack, low, terraform, CIS 3.4, MITRE T1583.002, CWE-327, D3-ET",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ℹ️ STK-GCP-DNS-002 — Cloud DNS DNSSEC uses deprecated RSASHA1 algorithm

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-GCP-DNS-002" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-GCP-DNS-002" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-GCP-DNS-002 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud DNS DNSSEC uses deprecated RSASHA1 algorithm.** This rule has `default_urgency: LOW` and operates on a single resource blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_dns_managed_zone` matching `/algorithm\s*=\s*"rsasha1"/` — _the resource body matches a regex inside the block._
  `google_dns_managed_zone.dnssec_config.default_key_specs.algorithm = "rsasha1"`.
RSASHA1 is deprecated by RFC 8624 and NIST SP 800-57; modern DNS
resolvers may downgrade or refuse to validate signatures.

## Why it likely fired

`google_dns_managed_zone.dnssec_config.default_key_specs.algorithm = "rsasha1"`.
RSASHA1 is deprecated by RFC 8624 and NIST SP 800-57; modern DNS
resolvers may downgrade or refuse to validate signatures.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-GCP-DNS-002` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Use a NIST-approved algorithm (`rsasha256`, `ecdsap256sha256`, or
`ecdsap384sha384`):

    resource "google_dns_managed_zone" "main" {
      # ...
      dnssec_config {
        state = "on"
        default_key_specs {
          algorithm  = "ecdsap256sha256"
          key_type   = "zoneSigning"
          key_length = 256
        }
      }
    }

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "google_dns_managed_zone" "example" {
  name        = "example"
  dns_name    = "example.com."
  description = "primary"
  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm  = "ecdsap256sha256"
      key_type   = "zoneSigning"
      key_length = 256
    }
  }
}
```

## Verification

```sh
`gcloud dns managed-zones describe <name> --format=json | \
  jq '.dnssecConfig.defaultKeySpecs[].algorithm'` must not contain
`rsasha1`.
```

## References

**CIS Benchmark**
  - `CIS 3.4`

**PCI-DSS**
  - `Req-4.1`

**MITRE ATT&CK**
  - [`T1583.002`](https://attack.mitre.org/techniques/T1583/002/)

**CWE**
  - [`CWE-327`](https://cwe.mitre.org/data/definitions/327.html)

**MITRE D3FEND**
  - [`D3-ET`](https://d3fend.mitre.org/technique/D3-ET/)

**NIST CSF 2.0**
  - [`PR.DS-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SC-13`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sc-13)

**Source**
  - [`catalog/STK-GCP-DNS-002.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-GCP-DNS-002.yaml) — canonical YAML

## Family

See also rules in the `STK-GCP-DNS-*` family:

- [`STK-GCP-DNS-001`](./STK-GCP-DNS-001.md) — Cloud DNS managed zone missing DNSSEC

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-GCP-DNS-002    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-GCP-DNS-002` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-GCP-DNS-002
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
