---
title: "STK-AZURE-WEBAPP-RUNTIME-001 — Azure App Service Web App uses end-of-life runtime"
description: "tf-analyze rule STK-AZURE-WEBAPP-RUNTIME-001 (MEDIUM · stack): Azure App Service Web App uses end-of-life runtime"
keywords: "stack, medium, terraform, iac, azure, mitre-T1195.002, cwe-1104, d3-sca, nist-csf-id.sc-2, nist-800-53-sr-4, slsa-deps"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-AZURE-WEBAPP-RUNTIME-001 \u2014 Azure App Service Web App uses end-of-life runtime",
  "description": "Upgrade to a supported runtime. Azure App Service supported\nversions (May 2026):\n- Python: 3.10, 3.11, 3.12, 3.13\n- Node.js: 20, 22\n- .NET: 8, 9\n- Java: 17, 21\n- PHP: 8.2, 8.3, 8.4",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-WEBAPP-RUNTIME-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-AZURE-WEBAPP-RUNTIME-001/"
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
  "keywords": "stack, medium, terraform, MITRE T1195.002, CWE-1104, D3-SCA",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# 💡 STK-AZURE-WEBAPP-RUNTIME-001 — Azure App Service Web App uses end-of-life runtime

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-AZURE-WEBAPP-RUNTIME-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-AZURE-WEBAPP-RUNTIME-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-AZURE-WEBAPP-RUNTIME-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Azure App Service Web App uses end-of-life runtime.** This rule has `default_urgency: MEDIUM` and operates on a single resource blast radius. 

## What this checks

1. **`resource_arg`** on `azurerm_linux_web_app` (`site_config.application_stack.python_version`) matching `/^3\.[678]$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Linux Web App uses an EOL Python runtime (3.6-3.8)
2. **`resource_arg`** on `azurerm_linux_web_app` (`site_config.application_stack.node_version`) matching `/^~?(10|12|14|16)(-lts)?$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Linux Web App uses an EOL Node.js runtime (10-16)
3. **`resource_arg`** on `azurerm_linux_web_app` (`site_config.application_stack.dotnet_version`) matching `/^v?(3\.1|5\.0|6\.0)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Linux Web App uses an EOL .NET runtime (3.1, 5.0, 6.0)
4. **`resource_arg`** on `azurerm_linux_web_app` (`site_config.application_stack.java_version`) matching `/^(1\.8|8|11)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Linux Web App uses an EOL Java runtime (8, 11)
5. **`resource_arg`** on `azurerm_linux_web_app` (`site_config.application_stack.php_version`) matching `/^(7\.[234]|8\.0)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Linux Web App uses an EOL PHP runtime (7.x, 8.0)
6. **`resource_arg`** on `azurerm_linux_web_app` (`site_config.application_stack.ruby_version`) matching `/^2\.[567]$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Linux Web App uses an EOL Ruby runtime (2.5-2.7)
7. **`resource_arg`** on `azurerm_windows_web_app` (`site_config.application_stack.node_version`) matching `/^~?(10|12|14|16)(-lts)?$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Windows Web App uses an EOL Node.js runtime (10-16)
8. **`resource_arg`** on `azurerm_windows_web_app` (`site_config.application_stack.dotnet_version`) matching `/^v?(3\.1|5\.0|6\.0)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Windows Web App uses an EOL .NET runtime (3.1, 5.0, 6.0)
9. **`resource_arg`** on `azurerm_windows_web_app` (`site_config.application_stack.java_version`) matching `/^(1\.8|8|11)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Windows Web App uses an EOL Java runtime (8, 11)
10. **`resource_arg`** on `azurerm_windows_web_app` (`site_config.application_stack.php_version`) matching `/^(7\.[234]|8\.0)$/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  Windows Web App uses an EOL PHP runtime (7.x, 8.0)

## Why it likely fired

Linux Web App uses an EOL Python runtime (3.6-3.8)

Linux Web App uses an EOL Node.js runtime (10-16)

Linux Web App uses an EOL .NET runtime (3.1, 5.0, 6.0)

Linux Web App uses an EOL Java runtime (8, 11)

Linux Web App uses an EOL PHP runtime (7.x, 8.0)

Linux Web App uses an EOL Ruby runtime (2.5-2.7)

Windows Web App uses an EOL Node.js runtime (10-16)

Windows Web App uses an EOL .NET runtime (3.1, 5.0, 6.0)

Windows Web App uses an EOL Java runtime (8, 11)

Windows Web App uses an EOL PHP runtime (7.x, 8.0)

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-AZURE-WEBAPP-RUNTIME-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Upgrade to a supported runtime. Azure App Service supported
versions (May 2026):
- Python: 3.10, 3.11, 3.12, 3.13
- Node.js: 20, 22
- .NET: 8, 9
- Java: 17, 21
- PHP: 8.2, 8.3, 8.4

## Suggested fix (`fix_hcl`)

![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)

```hcl
resource "azurerm_linux_web_app" "example" {
  name                = "example"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  service_plan_id     = azurerm_service_plan.example.id
  site_config {
    application_stack {
      python_version = "3.12"
    }
  }
}
```

## Verification

```sh
`az webapp config show -g <rg> -n <name> --query 'linuxFxVersion'`
must reference a currently-supported runtime.
```

## References

**MITRE ATT&CK**
  - [`T1195.002`](https://attack.mitre.org/techniques/T1195/002/)

**CWE**
  - [`CWE-1104`](https://cwe.mitre.org/data/definitions/1104.html)

**MITRE D3FEND**
  - [`D3-SCA`](https://d3fend.mitre.org/technique/D3-SCA/)

**NIST CSF 2.0**
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**SLSA v1.0**
  - [`SLSA deps`](https://slsa.dev/spec/v1.0/deps-track)

**Source**
  - [`catalog/STK-AZURE-WEBAPP-RUNTIME-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-AZURE-WEBAPP-RUNTIME-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-AZURE-WEBAPP-RUNTIME-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-AZURE-WEBAPP-RUNTIME-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-AZURE-WEBAPP-RUNTIME-001
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
