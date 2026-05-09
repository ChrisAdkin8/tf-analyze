---
title: "SEC-GCP-SQL-PUBLIC-001 — Cloud SQL instance permits public IPv4"
description: "tf-analyze rule SEC-GCP-SQL-PUBLIC-001 (HIGH · security): Cloud SQL instance permits public IPv4"
keywords: "security, high, terraform, iac, gcp, cis-6.6"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-GCP-SQL-PUBLIC-001 \u2014 Cloud SQL instance permits public IPv4",
  "description": "Set `ipv4_enabled = false` and use Private Service Connect or a\nPrivate IP allocation:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SQL-PUBLIC-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-GCP-SQL-PUBLIC-001/"
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
  "keywords": "security, high, terraform, CIS 6.6",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-GCP-SQL-PUBLIC-001 — Cloud SQL instance permits public IPv4

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-GCP-SQL-PUBLIC-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Cloud SQL instance permits public IPv4.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`resource_body_contains`** on `google_sql_database_instance` matching `/ipv4_enabled\s*=\s*true/` — _the resource body matches a regex inside the block._
  `google_sql_database_instance.settings.ip_configuration.ipv4_enabled = true`
assigns the instance a public IPv4 address. Even with
`authorized_networks` set, this exposes the SQL endpoint outside
the VPC perimeter — any network reachability mistake is now an
exfiltration path.

## Why it likely fired

`google_sql_database_instance.settings.ip_configuration.ipv4_enabled = true`
assigns the instance a public IPv4 address. Even with
`authorized_networks` set, this exposes the SQL endpoint outside
the VPC perimeter — any network reachability mistake is now an
exfiltration path.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-GCP-SQL-PUBLIC-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Set `ipv4_enabled = false` and use Private Service Connect or a
Private IP allocation:

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }

If a temporary public IP is needed for a one-off migration, gate it
behind a `count` driven by a tfvar (`var.allow_public_ip`) and
default to false. Document the migration window in CLAUDE.md.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "google_sql_database_instance" "example" {
  name             = "example"
  database_version = "POSTGRES_14"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}
```

## Verification

After applying, run:

    gcloud sql instances describe <name> \\
      --format='value(ipAddresses[].type)'

Should print only `PRIVATE` (no `PRIMARY`).

## References

**CIS Benchmark**
  - `CIS 6.6`

**Related rules**
  - [`STK-CLOUDSQL-002`](./STK-CLOUDSQL-002.md)

**Source**
  - [`catalog/SEC-GCP-SQL-PUBLIC-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-GCP-SQL-PUBLIC-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-GCP-SQL-PUBLIC-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-GCP-SQL-PUBLIC-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-GCP-SQL-PUBLIC-001
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
