---
title: "SEC-AZURE-VM-001 — Linux VM allows SSH password authentication"
description: "tf-analyze rule SEC-AZURE-VM-001 (HIGH · security): Linux VM allows SSH password authentication"
keywords: "security, high, terraform, iac, azure, cis-7.3"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-AZURE-VM-001 \u2014 Linux VM allows SSH password authentication",
  "description": "Disable password authentication and supply an SSH public key:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-VM-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-AZURE-VM-001/"
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
  "keywords": "security, high, terraform, CIS 7.3",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-AZURE-VM-001 — Linux VM allows SSH password authentication

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: single-resource](https://img.shields.io/badge/blast%20radius-single--resource-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-AZURE-VM-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Linux VM allows SSH password authentication.** This rule has `default_urgency: HIGH` and operates on a single resource blast radius. 

## What this checks

1. **`resource_missing_arg`** on `azurerm_linux_virtual_machine` (`disable_password_authentication`) — _the resource is missing a required attribute (or nested attribute path)._
  `azurerm_linux_virtual_machine` has no `disable_password_authentication`
argument. The default is `false` — SSH password logins are permitted.
Brute-force and credential-stuffing attacks against port 22 are
constant on Azure public IPs.
2. **`resource_arg`** on `azurerm_linux_virtual_machine` (`disable_password_authentication`) matching `/false/` — _the resource declares the named attribute, but its value matches the rule's pattern._
  `azurerm_linux_virtual_machine` explicitly sets
`disable_password_authentication = false`. Password-based SSH
authentication is confirmed; the attack surface for brute-force
and leaked credential reuse is fully open.

## Why it likely fired

`azurerm_linux_virtual_machine` has no `disable_password_authentication`
argument. The default is `false` — SSH password logins are permitted.
Brute-force and credential-stuffing attacks against port 22 are
constant on Azure public IPs.

`azurerm_linux_virtual_machine` explicitly sets
`disable_password_authentication = false`. Password-based SSH
authentication is confirmed; the attack surface for brute-force
and leaked credential reuse is fully open.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-AZURE-VM-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Disable password authentication and supply an SSH public key:

    resource "azurerm_linux_virtual_machine" "app" {
      # ...
      disable_password_authentication = true

      admin_ssh_key {
        username   = "azureuser"
        public_key = data.azurerm_key_vault_secret.ssh_pubkey.value
      }
    }

Store SSH public keys in Key Vault (`data.azurerm_key_vault_secret`)
rather than hardcoding them in source or tfvars. Enforce across all VMs
via Azure Policy: `"Audit Linux machines that allow remote connections
from accounts without passwords"` (built-in policy definition).

## Suggested fix (`fix_hcl`)

![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)

```hcl
resource "azurerm_linux_virtual_machine" "example" {
  # ... other arguments ...
  disable_password_authentication = true
  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
}
```

## Verification

```sh
`az vm show -g <rg> -n <name> \
  --query osProfile.linuxConfiguration.disablePasswordAuthentication`
must return `true`.
```

## References

**CIS Benchmark**
  - `CIS 7.3`

**PCI-DSS**
  - `Req-8.2`

**Source**
  - [`catalog/SEC-AZURE-VM-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-AZURE-VM-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-AZURE-VM-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-AZURE-VM-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-AZURE-VM-001
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
