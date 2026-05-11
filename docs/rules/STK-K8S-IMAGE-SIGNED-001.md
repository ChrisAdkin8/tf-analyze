---
title: "STK-K8S-IMAGE-SIGNED-001 — Kubernetes pod or container references an image without a signature/digest pin"
description: "tf-analyze rule STK-K8S-IMAGE-SIGNED-001 (HIGH · stack): Kubernetes pod or container references an image without a signature/digest pin"
keywords: "stack, high, terraform, iac, mitre-T1525, mitre-T1574.002, cwe-345, cwe-1357, nist-csf-pr.ds-6, nist-csf-id.sc-2, nist-800-53-si-7, nist-800-53-sr-4, csa-ccm-sta-04, slsa-l2, slsa-build"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "STK-K8S-IMAGE-SIGNED-001 \u2014 Kubernetes pod or container references an image without a signature/digest pin",
  "description": "Pin every image to a SHA256 digest:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-IMAGE-SIGNED-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/STK-K8S-IMAGE-SIGNED-001/"
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
  "keywords": "stack, high, terraform, MITRE T1525, MITRE T1574.002, CWE-345, CWE-1357",
  "proficiencyLevel": "Expert",
  "articleSection": "stack",
  "isAccessibleForFree": true
}
</script>

# ⚠️ STK-K8S-IMAGE-SIGNED-001 — Kubernetes pod or container references an image without a signature/digest pin

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: stack](https://img.shields.io/badge/section-stack-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square) ![Status: stub](https://img.shields.io/badge/status-stub-grey?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/STK-K8S-IMAGE-SIGNED-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=STK-K8S-IMAGE-SIGNED-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add STK-K8S-IMAGE-SIGNED-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Kubernetes pod or container references an image without a signature/digest pin.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/image\s*=\s*"(?!.*@sha256:)[^"]+:latest"/` — _a textual regex matched somewhere in the file._
  K8s container image with `:latest` tag, no SHA pin

## Why it likely fired

K8s container image with `:latest` tag, no SHA pin

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain STK-K8S-IMAGE-SIGNED-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Pin every image to a SHA256 digest:

    image = "ghcr.io/my-org/api@sha256:c97da1b6...c8a3"

And verify upstream with cosign at build time so the image's
signature appears in your registry. NSA Kubernetes Hardening
Guidance + SLSA L2 both require digest-pinned, signed images.

## Verification

```sh
`kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | grep -v '@sha256:'`
Empty output = compliant.
```

## References

**MITRE ATT&CK**
  - [`T1525`](https://attack.mitre.org/techniques/T1525/)
  - [`T1574.002`](https://attack.mitre.org/techniques/T1574/002/)

**CWE**
  - [`CWE-345`](https://cwe.mitre.org/data/definitions/345.html)
  - [`CWE-1357`](https://cwe.mitre.org/data/definitions/1357.html)

**NIST CSF 2.0**
  - [`PR.DS-6`](https://www.nist.gov/cyberframework)
  - [`ID.SC-2`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`SI-7`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=si-7)
  - [`SR-4`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=sr-4)

**CSA CCM v4**
  - [`STA-04`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA L2`](https://slsa.dev/spec/v1.0/levels#l2)
  - [`SLSA build`](https://slsa.dev/spec/v1.0/build-track)

**OWASP (namespaced)**
  - `K04`

**Source**
  - [`catalog/STK-K8S-IMAGE-SIGNED-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/STK-K8S-IMAGE-SIGNED-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain STK-K8S-IMAGE-SIGNED-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore STK-K8S-IMAGE-SIGNED-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - STK-K8S-IMAGE-SIGNED-001
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
