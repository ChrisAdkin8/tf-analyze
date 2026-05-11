---
title: "SEC-CICD-001 — Workflow file applies Terraform without required-reviewers gate"
description: "tf-analyze rule SEC-CICD-001 (HIGH · cicd): Workflow file applies Terraform without required-reviewers gate"
keywords: "cicd, high, terraform, iac, mitre-T1199, mitre-T1078.004, cwe-732, nist-csf-pr.ac-4, nist-csf-gv.po-1, nist-800-53-ac-3, nist-800-53-ac-6, csa-ccm-iam-09, slsa-l3, slsa-build"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-CICD-001 \u2014 Workflow file applies Terraform without required-reviewers gate",
  "description": "Wrap the apply job in a GitHub `environment:` declaring\n`required_reviewers`:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-CICD-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-CICD-001/"
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
  "keywords": "cicd, high, terraform, MITRE T1199, MITRE T1078.004, CWE-732",
  "proficiencyLevel": "Expert",
  "articleSection": "cicd",
  "isAccessibleForFree": true
}
</script>

# ⚠️ SEC-CICD-001 — Workflow file applies Terraform without required-reviewers gate

![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square) ![Section: cicd](https://img.shields.io/badge/section-cicd-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-CICD-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-CICD-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-CICD-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Workflow file applies Terraform without required-reviewers gate.** This rule has `default_urgency: HIGH` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/terraform\s+apply/` — _a textual regex matched somewhere in the file._
  `terraform apply` without an `environment:` block gating
`required_reviewers` lets a compromised PAT or workflow file
push infrastructure changes without human review.

## Why it likely fired

`terraform apply` without an `environment:` block gating
`required_reviewers` lets a compromised PAT or workflow file
push infrastructure changes without human review.

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-CICD-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Wrap the apply job in a GitHub `environment:` declaring
`required_reviewers`:

    jobs:
      apply:
        environment:
          name: production
          url: ${{ vars.STATE_URL }}
        steps:
          - run: terraform apply -auto-approve

Configure the protected `production` environment under
Repository → Settings → Environments to require at least one
reviewer, with a wait timer if your release cadence allows.

SLSA L3 expects every `apply` to be hermetic and reviewer-gated;
NIST SSDF PO.4.1 requires an authorisation trail before
production changes.

## Verification

Open the workflow YAML and confirm the apply job declares an
`environment:` block with a `name:` pointing at a protected
environment.

## References

**MITRE ATT&CK**
  - [`T1199`](https://attack.mitre.org/techniques/T1199/)
  - [`T1078.004`](https://attack.mitre.org/techniques/T1078/004/)

**CWE**
  - [`CWE-732`](https://cwe.mitre.org/data/definitions/732.html)

**NIST CSF 2.0**
  - [`PR.AC-4`](https://www.nist.gov/cyberframework)
  - [`GV.PO-1`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AC-3`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-3)
  - [`AC-6`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=ac-6)

**CSA CCM v4**
  - [`IAM-09`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**SLSA v1.0**
  - [`SLSA L3`](https://slsa.dev/spec/v1.0/levels#l3)
  - [`SLSA build`](https://slsa.dev/spec/v1.0/build-track)

**OWASP (namespaced)**
  - `CICD-SEC-1`
  - `CICD-SEC-3`

**Source**
  - [`catalog/SEC-CICD-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-CICD-001.yaml) — canonical YAML

## Family

See also rules in the `SEC-CICD-*` family:

- [`SEC-CICD-002`](./SEC-CICD-002.md) — Workflow uses `permissions: write-all` or omits minimum scopes
- [`SEC-CICD-003`](./SEC-CICD-003.md) — Apply job missing `environment:` with required_reviewers for production

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-CICD-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-CICD-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-CICD-001
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
