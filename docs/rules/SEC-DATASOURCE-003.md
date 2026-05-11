---
title: "SEC-DATASOURCE-003 — `data \\"external\\"` or `data \\"http\\"` runs at plan time"
description: "tf-analyze rule SEC-DATASOURCE-003 (HIGH · security): `data \'external\'` or `data \'http\'` runs at plan time"
keywords: "security, high, terraform, iac, mitre-T1059, mitre-T1071.001, cwe-829, cwe-78, nist-csf-pr.ds-6, nist-800-53-si-3, nist-800-53-cm-7, csa-ccm-tvm-04, slsa-build"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-DATASOURCE-003 \u2014 `data \\\"external\\\"` or `data \\\"http\\\"` runs at plan time",
  "description": "* **`data \"external\"`** \u2014 replace with `data \"aws_ami\"`, a Terraform\n  provider data source, or pre-computed values stored in the\n  workspace's variables. If you genuinely need a shell-out, gate\n  it behind a `terraform_data` resource and C",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-DATASOURCE-003/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-DATASOURCE-003/"
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
  "keywords": "security, high, terraform, MITRE T1059, MITRE T1071.001, CWE-829, CWE-78",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-DATASOURCE-003 — `data \"external\"` or `data \"http\"` runs at plan time

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: module](https://img.shields.io/badge/blast%20radius-module-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-DATASOURCE-003" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-DATASOURCE-003" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-DATASOURCE-003 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **`data \"external\"` or `data \"http\"` runs at plan time.** This rule has `default_urgency: HIGH` and operates on a module blast radius. 

## What this checks

1. **`grep`** matching `/^\s*data\s+"(?:external|http)"\s+/` — _a textual regex matched somewhere in the file._
  `data "external"` runs an external program at plan AND apply
time; `data "http"` fetches a URL whose body shapes downstream
resources. Both lift remote, mutable input into the plan
graph — a compromised endpoint or interpreter changes infra
under you with no audit trail. Common consumers of `data "http"`:
pulling latest AMIs, fetching SAML metadata, retrieving CIDR
lists — every one of which has a static or version-pinned
alternative.

## Why it likely fired

`data "external"` runs an external program at plan AND apply
time; `data "http"` fetches a URL whose body shapes downstream
resources. Both lift remote, mutable input into the plan
graph — a compromised endpoint or interpreter changes infra
under you with no audit trail. Common consumers of `data "http"`:
pulling latest AMIs, fetching SAML metadata, retrieving CIDR
lists — every one of which has a static or version-pinned
alternative.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-DATASOURCE-003` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

* **`data "external"`** — replace with `data "aws_ami"`, a Terraform
  provider data source, or pre-computed values stored in the
  workspace's variables. If you genuinely need a shell-out, gate
  it behind a `terraform_data` resource and CI-controlled checksums.
* **`data "http"`** — replace with provider data sources (most
  cloud providers expose what you need); if you must fetch, pin
  via `checksum_sha256` once Terraform adds it, or use a versioned
  artifact registry.

## Verification

```sh
`grep -rE 'data\s+"(external|http)"' --include="*.tf"`. Each match
needs a justification comment or a replacement.
```

## References

**MITRE ATT&CK**
  - [`T1059`](https://attack.mitre.org/techniques/T1059/)
  - [`T1071.001`](https://attack.mitre.org/techniques/T1071/001/)

**CWE**
  - [`CWE-829`](https://cwe.mitre.org/data/definitions/829.html)
  - [`CWE-78`](https://cwe.mitre.org/data/definitions/78.html)

**NIST CSF 2.0**
  - [`PR.DS-6`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SI-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-3)
  - [`CM-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=cm-7)

**CSA CCM v4**
  - [`TVM-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA build`](https://slsa.dev/spec/v1.0/build-track)

**OWASP (namespaced)**
  - `CICD-SEC-4`

**Source**
  - [`catalog/SEC-DATASOURCE-003.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-DATASOURCE-003.yaml) — canonical YAML

## Family

See also rules in the `SEC-DATASOURCE-*` family:

- [`SEC-DATASOURCE-001`](./SEC-DATASOURCE-001.md) — External or HTTP data source executes at plan time
- [`SEC-DATASOURCE-002`](./SEC-DATASOURCE-002.md) — data.external program takes user-controlled input

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-DATASOURCE-003    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-DATASOURCE-003` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-DATASOURCE-003
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
