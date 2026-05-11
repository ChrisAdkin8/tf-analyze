---
title: "SEC-LOG-CROSS-ACCOUNT-001 — Audit log destination is in the same AWS account (no cross-account isolation)"
description: "tf-analyze rule SEC-LOG-CROSS-ACCOUNT-001 (MEDIUM · security): Audit log destination is in the same AWS account (no cross-account isolation)"
keywords: "security, medium, terraform, iac, mitre-T1070.001, mitre-T1565, cwe-778, nist-csf-pr.pt-1, nist-csf-de.ae-3, nist-800-53-au-9-2, nist-800-53-au-11, csa-ccm-log-08"
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "SEC-LOG-CROSS-ACCOUNT-001 \u2014 Audit log destination is in the same AWS account (no cross-account isolation)",
  "description": "Create a dedicated `security-logs` AWS account; ship every\naccount's audit output to a bucket in that account via cross-account\nbucket policy + replication. CloudTrail organization trail is the\ncanonical pattern:",
  "url": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-LOG-CROSS-ACCOUNT-001/",
  "mainEntityOfPage": {
    "@type": "WebPage",
    "@id": "https://chrisadkin8.github.io/tf-analyze/rules/SEC-LOG-CROSS-ACCOUNT-001/"
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
  "keywords": "security, medium, terraform, MITRE T1070.001, MITRE T1565, CWE-778",
  "proficiencyLevel": "Expert",
  "articleSection": "security",
  "isAccessibleForFree": true
}
</script>

# 💡 SEC-LOG-CROSS-ACCOUNT-001 — Audit log destination is in the same AWS account (no cross-account isolation)

![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square) ![Section: security](https://img.shields.io/badge/section-security-blue?style=flat-square) ![Blast radius: environment](https://img.shields.io/badge/blast%20radius-environment-purple?style=flat-square) ![Status: stub](https://img.shields.io/badge/status-stub-grey?style=flat-square)

<p><a href="vscode://tfanalyze.tf-analyze/rule/SEC-LOG-CROSS-ACCOUNT-001" style="display:inline-block;padding:6px 12px;background:#157878;color:#fff;text-decoration:none;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px">📂 Open in VS Code</a><a href="vscode://tfanalyze.tf-analyze/suppress?id=SEC-LOG-CROSS-ACCOUNT-001" style="display:inline-block;padding:6px 12px;background:#fff;color:#c27a00;text-decoration:none;border:1px solid #c27a00;border-radius:4px;font-weight:600;font-size:14px;margin-top:6px;margin-left:6px" title="Add SEC-LOG-CROSS-ACCOUNT-001 to .tf-analyze.yaml's ignore_rules in your workspace">📝 Suppress in workspace</a> <span style="color:#666;font-size:12px;margin-left:4px">(requires the <a href="https://marketplace.visualstudio.com/items?itemName=tfanalyze.tf-analyze" style="color:#157878">tf-analyze extension</a>)</span></p>

> **Audit log destination is in the same AWS account (no cross-account isolation).** This rule has `default_urgency: MEDIUM` and operates on a environment blast radius. 

## What this checks

1. **`grep`** matching `/cloudtrail.*\bs3_bucket_name\s*=\s*"(?!arn:aws:s3:::audit-logs-)[^"]*"/` — _a textual regex matched somewhere in the file._
  Audit logs (CloudTrail / VPC Flow Logs / GuardDuty) should ship
to a bucket in a *different* AWS account dedicated to security
operations. An attacker who compromises the production account
can otherwise erase or tamper with the very logs that would
reveal their presence (NIST AU-9(2) — "Audit Information Off
System"; OWASP A09).

## Why it likely fired

Audit logs (CloudTrail / VPC Flow Logs / GuardDuty) should ship
to a bucket in a *different* AWS account dedicated to security
operations. An attacker who compromises the production account
can otherwise erase or tamper with the very logs that would
reveal their presence (NIST AU-9(2) — "Audit Information Off
System"; OWASP A09).

## Adversarial scenario

HIGH and CRITICAL findings carry a 3–4 sentence adversarial narrative grounded in real incidents (Capital One, Accenture, SolarWinds). Run `python3 scripts/detect.py --explain SEC-LOG-CROSS-ACCOUNT-001` or hover the squiggle in the VS Code extension to see the rendered narrative for this rule.

Narratives are baked into the engine ([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py)) under `_ATTACK_NARRATIVES` and emitted into the JSON output as the `narrative` field on every finding for this rule.

## Remediation

Create a dedicated `security-logs` AWS account; ship every
account's audit output to a bucket in that account via cross-account
bucket policy + replication. CloudTrail organization trail is the
canonical pattern:

    resource "aws_cloudtrail" "org" {
      name           = "org-trail"
      s3_bucket_name = "arn:aws:s3:::audit-logs-${var.security_account_id}"
      is_organization_trail = true
    }

## Verification

```sh
`aws cloudtrail describe-trails --query 'trailList[*].S3BucketName'` —
every entry should point at the security-account bucket.
```

## References

**MITRE ATT&CK**
  - [`T1070.001`](https://attack.mitre.org/techniques/T1070/001/)
  - [`T1565`](https://attack.mitre.org/techniques/T1565/)

**CWE**
  - [`CWE-778`](https://cwe.mitre.org/data/definitions/778.html)

**NIST CSF 2.0**
  - [`PR.PT-1`](https://www.nist.gov/cyberframework)
  - [`DE.AE-3`](https://www.nist.gov/cyberframework)

**NIST SP 800-53 Rev. 5**
  - [`AU-9(2)`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-9-2)
  - [`AU-11`](https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=au-11)

**CSA CCM v4**
  - [`LOG-08`](https://cloudsecurityalliance.org/research/cloud-controls-matrix)

**OWASP (namespaced)**
  - `A09`

**Source**
  - [`catalog/SEC-LOG-CROSS-ACCOUNT-001.yaml`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/SEC-LOG-CROSS-ACCOUNT-001.yaml) — canonical YAML

---

## Run this check

```sh
python3 scripts/detect.py --explain SEC-LOG-CROSS-ACCOUNT-001    # full catalogue entry
python3 scripts/detect.py --target . --only-fixture <fixture>
```

## Suppress

Inline (single occurrence): `# tf-analyze:ignore SEC-LOG-CROSS-ACCOUNT-001` on or above the offending line.

Project-wide: add to `.tf-analyze.yaml`:

```yaml
ignore_rules:
  - SEC-LOG-CROSS-ACCOUNT-001
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
