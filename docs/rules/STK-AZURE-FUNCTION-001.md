---
title: "STK-AZURE-FUNCTION-001 — Azure Function App uses end-of-life runtime"
description: "tf-analyze rule STK-AZURE-FUNCTION-001 (HIGH · stack): Azure Function App uses end-of-life runtime"
keywords: "stack, high, terraform, iac, azure, mitre-T1190, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, csa-ccm-ais-07, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-FUNCTION-001 \u2014 Azure Function App uses end-of-life runtime",
  "description": "Upgrade the runtime to a supported version. Current Azure Functions\nsupported runtimes (May 2026):\n- Python: 3.10, 3.11, 3.12\n- Node.js: 18, 20\n- .NET: 8 (isolated), 9 (preview)\n- Java: 17, 21",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-FUNCTION-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-FUNCTION-001/"
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
  "keywords": "stack, high, terraform, MITRE T1190, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-AZURE-FUNCTION-001 — Azure Function App uses end-of-life runtime

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-FUNCTION-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-FUNCTION-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-FUNCTION-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure Function App uses end-of-life runtime.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_linux_function_app` (`site_config.application_stack.python_version`) matching `/^(3\.6|3\.7|3\.8)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Function App Python runtime out of support
2. **`resource_body_contains`** on `azurerm_linux_function_app` matching `/python_version\s*=\s*"(3\.6|3\.7|3\.8)"/` — _the resource body matches a regex inside the block._
  Function App Python runtime out of support (regex body match)
3. **`resource_body_contains`** on `azurerm_linux_function_app` matching `/node_version\s*=\s*"(10|12|14|16)"/` — _the resource body matches a regex inside the block._
  Function App Node.js runtime out of support
4. **`resource_body_contains`** on `azurerm_linux_function_app` matching `/dotnet_version\s*=\s*"(v3\.1|v5\.0|v6\.0)"/` — _the resource body matches a regex inside the block._
  Function App .NET runtime out of support
5. **`resource_body_contains`** on `azurerm_linux_function_app` matching `/java_version\s*=\s*"(8|11)"/` — _the resource body matches a regex inside the block._
  Function App Java runtime out of support
6. **`resource_body_contains`** on `azurerm_windows_function_app` matching `/(python_version|node_version|dotnet_version|java_version)\s*=\s*"(3\.[678]|10|12|14|16|v3\.1|v5\.0|v6\.0|8|11)"/` — _the resource body matches a regex inside the block._
  Windows Function App runtime out of support

## Why it likely fired

Function App Python runtime out of support

Function App Python runtime out of support (regex body match)

Function App Node.js runtime out of support

Function App .NET runtime out of support

Function App Java runtime out of support

Windows Function App runtime out of support

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-FUNCTION-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade the runtime to a supported version. Current Azure Functions
supported runtimes (May 2026):
- Python: 3.10, 3.11, 3.12
- Node.js: 18, 20
- .NET: 8 (isolated), 9 (preview)
- Java: 17, 21

Test compatibility on a staging slot before swapping production.

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_linux_function_app" "example" {
  name                       = "example"
  resource_group_name        = azurerm_resource_group.example.name
  location                   = azurerm_resource_group.example.location
  service_plan_id            = azurerm_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key

  site_config {
    application_stack {
      python_version = "3.12"
    }
  }
}
```

_Runtime upgrades may break source compatibility (e.g. removed/changed stdlib APIs); test on a deployment slot first._

## Verification

```sh
`az functionapp config show --name <name> --resource-group <rg> \
  --query 'linuxFxVersion'` must return a supported runtime identifier
(e.g. `Python|3.12`, `Node|20`).
```

## References

**MITRE ATT&CK**
  - [`T1190`](https://attack.mitre.org/techniques/T1190/)
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**CSA CCM v4**
  - [`AIS-07`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-AZURE-FUNCTION-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-FUNCTION-001.yaml) — canonical YAML

## Family

See also rules in the `STK-AZURE-FUNCTION-*` family:

- [`STK-AZURE-FUNCTION-002`](./STK-AZURE-FUNCTION-002.md) — Azure Function App missing Application Insights instrumentation

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-FUNCTION-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-FUNCTION-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-FUNCTION-001
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
