---
title: "MOD-STALE-001 — Registry module is significantly behind latest version"
description: "tf-analyze rule MOD-STALE-001 (LOW · dry): Registry module is significantly behind latest version"
keywords: "dry, low, terraform, iac, mitre-T1195.002, cwe-1395, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, csa-ccm-sta-04, csa-ccm-ais-07, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "MOD-STALE-001 \u2014 Registry module is significantly behind latest version",
  "description": "Run `detect.py --check-registry` to identify modules pinned significantly behind their\nlatest published version on the Terraform Registry. Upgrade the `version` constraint and\nrun `terraform init -upgrade` to pull the newer release. Review ",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-STALE-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/MOD-STALE-001/"
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
  "keywords": "dry, low, terraform, MITRE T1195.002, CWE-1395, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "dry",
  "isAccessibleForFree": true
}
</script>

# ℹ️ MOD-STALE-001 — Registry module is significantly behind latest version

![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square) ![Section: dry](https://img.shields.io/badge/section-dry-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/MOD-STALE-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=MOD-STALE-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add MOD-STALE-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Registry module is significantly behind latest version.** This rule has `default_urgency: LOW` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/source\s*=\s*"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+"/` — _a textual regex matched somewhere in the file._
  Registry-style module source present (staleness checked via --check-registry)

## Why it likely fired

Registry-style module source present (staleness checked via --check-registry)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain MOD-STALE-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Run `detect.py --check-registry` to identify modules pinned significantly behind their
latest published version on the Terraform Registry. Upgrade the `version` constraint and
run `terraform init -upgrade` to pull the newer release. Review the module's CHANGELOG
for breaking changes before upgrading across major versions.

Staleness thresholds:
- MEDIUM: pinned version is >= 1 major version behind latest
- LOW: pinned version is >= 3 minor versions behind latest (within the same major)

Findings are only emitted by `--check-registry` (requires outbound HTTPS to
registry.terraform.io). The static pass records the source pattern but does not
query the registry — keeping normal scans offline-capable.

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
# Update the version constraint to the latest (check with --check-registry)
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.1"   # was ~> 3.0
}
```

## Verification

Run `terraform init -upgrade` and inspect `.terraform.lock.hcl` — the upgraded version
should match the latest from `terraform.io/registry/v1/modules/{ns}/{name}/{provider}`.
Confirm `terraform plan` shows no unintended resource replacements after the upgrade.

## References

**OWASP IaC Cheat Sheet**
  - [`Develop and Distribute / Open Source Dependency Scanning`](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1395`](https://cwe.mitre.org/data/definitions/1395.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**CSA CCM v4**
  - [`STA-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)
  - [`AIS-07`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/MOD-STALE-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/MOD-STALE-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain MOD-STALE-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore MOD-STALE-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - MOD-STALE-001
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
