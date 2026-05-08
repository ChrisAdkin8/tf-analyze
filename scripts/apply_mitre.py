#!/usr/bin/env python3
"""Apply MITRE ATT&CK technique mappings to the catalogue.

Reads the in-script manifest of ``rule_id -> [Tnnnn[.nnn], ...]`` and inserts
or updates a ``mitre:`` block in each YAML file. Idempotent: re-running won't
duplicate or reorder existing mappings.

Run:  python3 scripts/apply_mitre.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "catalog"

# Technique manifest. T-IDs come from https://attack.mitre.org/. Only mapped
# rules where the link is unambiguous; vague mappings hurt rather than help.
MAPPINGS: dict[str, list[str]] = {
    # Credentials, secrets, identity
    "SEC-AWS-IAM-001":             ["T1078.004"],
    "SEC-AWS-IAM-002":             ["T1078.004"],
    "SEC-AWS-IAM-003":             ["T1098.001", "T1078.004"],
    "SEC-AWS-IAM-ACCESSKEY-001":   ["T1552.001", "T1078.004"],
    "SEC-AWS-IAM-USER-001":        ["T1078.004"],
    "SEC-AWS-COGNITO-001":         ["T1556.006"],
    "SEC-CRED-001":                ["T1552.001"],
    "SEC-CRED-002":                ["T1552.001"],
    "SEC-PROVISIONER-001":         ["T1059"],
    "SEC-PROVIDER-PLAINTEXT-001":  ["T1552.001"],
    "SEC-DATASOURCE-001":          ["T1552.001"],
    "SEC-SENSITIVE-001":           ["T1552.001"],
    "SEC-SENSITIVE-002":           ["T1552.001"],
    "SEC-SENSITIVE-003":           ["T1552.001"],

    # Network exposure / public-facing
    "SEC-AWS-LB-LISTENER-001":     ["T1071.001"],
    "SEC-AWS-CLOUDFRONT-001":      ["T1071.001"],
    "SEC-AWS-CLOUDFRONT-002":      ["T1071.001"],
    "SEC-AWS-APIGW-001":           ["T1190"],
    "SEC-AWS-COGNITO-002":         ["T1190"],
    "SEC-AZURE-NSG-001":           ["T1190", "T1133"],
    "SEC-GCP-FW-001":              ["T1190", "T1133"],
    "SEC-GCP-FW-SSH-001":          ["T1133"],
    "SEC-GCP-FW-RDP-001":          ["T1133"],

    # Disabled defenses / impaired logging
    "SEC-AWS-CLOUDTRAIL-001":      ["T1562.008"],
    "SEC-AWS-CLOUDTRAIL-002":      ["T1562.008"],
    "SEC-AWS-VPC-FLOWLOGS-001":    ["T1562.008"],
    "SEC-AWS-CWL-001":             ["T1562.008"],
    "SEC-AWS-S3-LOGGING-001":      ["T1562.008"],
    "SEC-AWS-GUARDDUTY-001":       ["T1562.001"],
    "SEC-AWS-SECURITYHUB-001":     ["T1562.001"],
    "SEC-AWS-WAF-001":             ["T1562.004"],
    "SEC-AZURE-LOGGING-001":       ["T1562.008"],
    "SEC-AZURE-MONITOR-001":       ["T1562.008"],
    "SEC-GCP-LOGGING-001":         ["T1562.008"],

    # Encryption-at-rest / key management
    "SEC-AWS-S3-001":              ["T1530"],
    "SEC-AWS-EBS-001":             ["T1530"],
    "SEC-AWS-RDS-ENCRYPT-001":     ["T1530"],
    "SEC-AWS-DDB-001":             ["T1530"],
    "SEC-AWS-DOCDB-001":           ["T1530"],
    "SEC-AWS-REDSHIFT-001":        ["T1530"],
    "SEC-AWS-KINESIS-001":         ["T1530"],
    "SEC-AWS-NEPTUNE-001":         ["T1530"],
    "SEC-AZURE-SQL-001":           ["T1530"],
    "SEC-AZURE-KV-001":            ["T1530"],
    "SEC-AZURE-KV-002":            ["T1530", "T1133"],
    "SEC-GCP-CMEK-001":            ["T1530"],

    # IMDSv2 / container / metadata
    "SEC-AWS-EC2-IMDS-001":        ["T1552.005"],
    "STK-AWS-LAUNCH-TEMPLATE-001": ["T1552.005"],
    "SEC-AWS-ECS-001":             ["T1552.001"],
    "SEC-AWS-ECS-002":             ["T1611"],

    # Public storage objects
    "SEC-AWS-S3-PUBLIC-BLOCK-001": ["T1530"],
    "SEC-AWS-CLOUDFRONT-S3-001":   ["T1530"],
    "SEC-GCP-BUCKET-PUBLIC-001":   ["T1530"],

    # Provisioning / supply chain / state
    "SEC-STATE-001":               ["T1552.001"],
    "MOD-SUPPLY-001":              ["T1195.002"],
    "MOD-SUPPLY-002":              ["T1195.002"],
    "MOD-SUPPLY-003":              ["T1195.002"],
}


def insert_mitre(text: str, techniques: list[str]) -> str:
    """Insert or replace the `mitre:` block in a catalogue YAML.

    Inserts after the last of (cis:, pci_dss:, soc2_cc:) if any are present;
    otherwise after `status:`. Preserves trailing list items above the
    insertion point.
    """
    if "\nmitre:" in text or text.startswith("mitre:"):
        # Already has a block — replace it. Find from `mitre:` to the next
        # top-level field (line not starting with whitespace).
        lines = text.splitlines(keepends=True)
        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("mitre:"):
                # Skip the existing block (the line itself + indented children).
                i += 1
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                    i += 1
                # Emit the new block.
                out.append("mitre:\n")
                for t in techniques:
                    out.append(f'  - "{t}"\n')
                continue
            out.append(line)
            i += 1
        return "".join(out)

    # No existing block — find an anchor.
    lines = text.splitlines(keepends=True)
    anchor_idx = None
    for i, line in enumerate(lines):
        if line.startswith(("cis:", "pci_dss:", "soc2_cc:")):
            # Walk to end of this list block.
            j = i + 1
            while j < len(lines) and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                j += 1
            anchor_idx = j  # insert before lines[j]
    if anchor_idx is None:
        for i, line in enumerate(lines):
            if line.startswith("status:"):
                anchor_idx = i + 1
                break
    if anchor_idx is None:
        # Fallback — append before patterns:
        for i, line in enumerate(lines):
            if line.startswith("patterns:"):
                anchor_idx = i
                break
    if anchor_idx is None:
        return text  # give up

    insertion = ["mitre:\n"] + [f'  - "{t}"\n' for t in techniques]
    return "".join(lines[:anchor_idx] + insertion + lines[anchor_idx:])


def main() -> int:
    written = 0
    skipped_missing = 0
    for rule_id, techs in sorted(MAPPINGS.items()):
        path = CATALOG / f"{rule_id}.yaml"
        if not path.exists():
            print(f"  SKIP (no file): {rule_id}", file=sys.stderr)
            skipped_missing += 1
            continue
        original = path.read_text()
        updated = insert_mitre(original, techs)
        if updated != original:
            path.write_text(updated)
            written += 1
            print(f"  UPDATED {rule_id}: {techs}")
    print()
    print(f"Catalogue rules updated: {written}/{len(MAPPINGS)}  "
          f"(missing files: {skipped_missing})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
