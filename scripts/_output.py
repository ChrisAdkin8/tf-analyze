"""Output formatters — seventh seam in the detect.py modularisation.

Turns the engine's intermediate `findings` + `entries` lists into
every user-facing output format the CLI / SARIF consumers / VS Code
extension / docs site need:

  * SARIF v2.1 with structured taxonomies + per-rule relationships
    (CWE, MITRE ATT&CK, MITRE D3FEND, CIS) — `to_sarif`.
  * HTML report with executive view, compliance panel, fix-priority
    table, attack-graph embed — `to_html`.
  * GitHub PR-comment Markdown (`--format pr-summary`) — built by
    `_render_pr_summary` for the GitHub Action's worked example.
  * MITRE ATT&CK tactic-grouped view — `_render_mitre`.
  * Compliance gap reports for CIS / PCI-DSS / SOC 2 / OWASP IaC,
    rendered to text + HTML + OSCAL JSON — `_compliance_gap_report`,
    `_render_compliance_text/html`, `_compliance_to_oscal`.
  * Adversarial scenario narratives keyed by rule ID — the
    `_ATTACK_NARRATIVES` table (190 LOC of curated breach
    references: Capital One 2019 SSRF, SolarWinds 2020, Tesla 2020,
    etc.) plus the `_narrative_for_finding` lookup.

Scope rule — same as the prior six seams:

  * Pure functions + immutable data tables only.
  * No engine state. Each formatter takes `findings` (list of dicts)
    and (when needed) `entries` (catalogue rule dicts) as parameters,
    returns a string or dict.
  * Three cross-seam edges — every other module the formatters need
    is already extracted:
      * `_attack_graph.graph_to_mermaid`, `_render_graph_html`,
        `build_attack_graph` — `to_html` embeds the attack-graph
        view when an `attack_graph` block is present.
      * `_mitre.MITRE_ATTACK_VERSION`, `MITRE_TECHNIQUE_INFO`,
        `MITRE_TACTIC_ORDER`, `mitre_technique_name`,
        `mitre_technique_tactics` — `_render_mitre` + SARIF
        taxonomies need the technique table.
      * `_catalog.validate_catalog_entry` — `to_sarif` runs the
        validator when emitting taxonomies so any schema regression
        surfaces as a SARIF warning at output time.

Public surface
--------------

Constants
~~~~~~~~~

* ``RULE_DOCS_URL_BASE`` — `https://chrisadkin8.github.io/tf-analyze/rules/{id}/`.
  Used by compliance HTML, SARIF `helpUri`, Findings panel rule
  headers, VS Code hover panel — switching the canonical docs host
  is a single-line edit here.
* ``SARIF_HELP_URI_BASE`` — alias for ``RULE_DOCS_URL_BASE``. Kept
  separate so SARIF-consumer tooling that has hardcoded the name
  keeps working if we ever break them apart.
* ``_ATTACK_NARRATIVES`` — `{rule_id → markdown narrative}`. 190
  LOC of curated breach references used by `_narrative_for_finding`
  to render the adversarial-scenario block in HTML / PR-comment /
  per-rule-docs output.
* ``_FIX_DISRUPTION_LABELS`` — `{disruption_keyword → (HTML label,
  colour)}`. Drives the `_disruption_badge` renderer.

Functions
~~~~~~~~~

SARIF:
  * ``_sarif_fingerprint(finding)``
  * ``_sarif_taxonomies(entries)``
  * ``_sarif_rule_relationships(entry)``
  * ``to_sarif(findings, entries)``

Per-finding helpers:
  * ``_effective_urgency(finding, entry)``
  * ``_enrich_findings_for_output(findings, entries, ...)``
  * ``_narrative_for_finding(finding, entry)``
  * ``_disruption_badge(disruption)``

HTML report:
  * ``_render_executive_view(findings, ...)``
  * ``_render_fix_priority_html(scored)``
  * ``to_html(findings, entries, ...)``

Compliance:
  * ``_infer_cis_framework(rule_id)``
  * ``_compliance_gap_report(findings, entries, framework=...)``
  * ``_render_compliance_text(by_fw)``
  * ``_render_compliance_html(by_fw)``
  * ``_compliance_to_oscal(by_fw, target_dir="")``

MITRE + PR summary:
  * ``_render_mitre(findings, entries, ...)``
  * ``_append_attack_graph_block(parts, attack_graph)``
  * ``_render_pr_summary(...)``

Names are preserved exactly; the re-export shim in `detect.py`
maps each one as a binding so existing callers (the `--format`
dispatch in `main`, the VS Code extension's HTML/SARIF consumers,
`tests/test_output_formats.py`, `tests/test_sarif_taxonomies_and_refactor.py`,
`tests/test_pr_summary.py`, `tests/test_compliance_owasp_iac.py`)
need no migration.
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

# ---- cross-seam imports -------------------------------------------------

from _attack_graph import (
    build_attack_graph,
    graph_to_mermaid,
    _render_graph_html,
)
from _mitre import MITRE_ATTACK_VERSION
from _catalog import validate_catalog_entry


# ---- urgency rank — single source of truth ------------------------------
# Round-3 audit fix #11 — the urgency-rank table was previously defined
# inline at five sites in this module: the executive view (line 1048),
# the fix-priority HTML (line 1182), the compliance render (line 1501),
# and the find-display fallback (line 1553 — note the opposite sense:
# CRITICAL=4 high vs CRITICAL=0 low, which is what made the inline
# copies a drift hazard).
#
# Two canonical orderings, both centralised:
#
#   * ``URGENCY_RANK_ASCENDING`` — lower number = more severe. Used
#     anywhere a sort by urgency-then-other wants CRITICAL first via
#     `key=lambda x: URGENCY_RANK_ASCENDING.get(x["urgency"], …)`.
#   * ``URGENCY_RANK_DESCENDING`` — higher number = more severe. Used
#     in the few sites that pick the "largest" urgency via
#     `max(…, key=lambda u: URGENCY_RANK_DESCENDING[u])`.
#
# A future contributor bumping HIGH from 1 to 5 needs to touch only
# this file. The constants are intentionally exposed at module scope
# so the test suite can lock them.
URGENCY_RANK_ASCENDING: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}
URGENCY_RANK_DESCENDING: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


# ---- SARIF / JSON text safety ------------------------------------------
# SARIF message fields go through `json.dumps` so structural escapes are
# automatic, but a literal newline / control character in an
# engine-supplied field (resource name, file path) makes the SARIF
# message field render across multiple lines in less-strict consumers.
# Round-4 audit fix #19 — strip C0 control characters except tab.
def _sarif_safe_text(s: str) -> str:
    return "".join(c if c == "\t" or 0x20 <= ord(c) < 0x7f or ord(c) >= 0xa0 else " " for c in s)


# ---- HTML escape alias --------------------------------------------------
# Round-4 audit fix #1 / #2 — every engine-supplied field rendered into
# HTML must round-trip through ``html.escape``, otherwise a custom-
# catalogue rule title or a finding's resource name containing
# ``<img onerror=alert(1)>`` executes JS in any browser opening the
# rendered report. The R30.8 fix closed the same class in the VS Code
# extension's webview but missed the Python-side HTML emitters here.
#
# The short alias keeps every site readable while making the discipline
# uniform. Pass ``quote=True`` (the default) so attribute values are
# also safe, e.g. ``<a title="{_h(title)}">`` cannot break the
# attribute via a ``"``.
_h = html.escape


# ---- rule-docs canonical URL --------------------------------------------
# Single source of truth for the per-rule docs URL — drives:
#   - SARIF `helpUri` on every result + every rule definition
#   - compliance HTML rule-name links
#   - the HTML compliance panel
#   - the text compliance output
#   - the Findings panel rule headers
#   - the VS Code extension hover panel
# The catalogue YAML stays the source of truth; the docs site is a
# rendering of it. RULE_DOCS_URL_BASE is one place; switching the
# canonical host (e.g. to https://tf-analyze.dev/rules/...) is a single
# edit that ripples to every output surface.
# GitHub Pages serves Jekyll-rendered pages at pretty-URL paths
# (`/rules/SEC-AWS-IAM-001/`), not at `/rules/SEC-AWS-IAM-001.html` —
# the .html extension returns 404. Use the pretty form so every link
# from compliance HTML / SARIF helpUri / Findings panel / VS Code
# hover lands on the actual published page.
RULE_DOCS_URL_BASE = "https://chrisadkin8.github.io/tf-analyze/rules/{id}/"
SARIF_HELP_URI_BASE = RULE_DOCS_URL_BASE


def _sarif_fingerprint(finding: dict) -> dict:
    """Return partial fingerprints for SARIF.

    Two complementary keys:
    - tfAnalyze/v1: id|file|resource — changes when file is renamed (new/resolved pair)
    - tfAnalyze/v1-resource: id|resource — stable across file renames; GitHub Code
      Scanning uses the highest-specificity key that matches, so renaming a file
      no longer floods the "fixed" view with false positives when the resource
      name is preserved.
    """
    import hashlib
    fid = finding.get("id", "UNKNOWN")
    full_key = f"{fid}|{finding.get('file','')}|{finding.get('resource','')}"
    resource_key = f"{fid}|{finding.get('resource','')}"
    return {
        "tfAnalyze/v1": hashlib.sha256(full_key.encode()).hexdigest()[:16],
        "tfAnalyze/v1-resource": hashlib.sha256(resource_key.encode()).hexdigest()[:16],
    }


def _effective_urgency(finding: dict, entry: dict) -> str:
    """Return the urgency for a finding: reachability-adjusted if present, else catalogue default."""
    return finding.get("urgency") or entry.get("default_urgency", "MEDIUM")


def _enrich_findings_for_output(
    findings: list[dict], entries: list[dict]
) -> list[dict]:
    """Add `title`, `urgency`, `section`, `recommendation`, `fix_hcl`,
    `fix_disruption`, `mitre`, and `narrative` to each finding using the
    catalogue entry. Mutates in place and returns the same list for
    convenience.

    Skipped fields when missing from the entry — consumers (the VS Code
    extension, the LSP server, the demo web UI) all do `f.get(key)` and
    handle absence.
    """
    entry_map = {e["id"]: e for e in entries}
    for f in findings:
        e = entry_map.get(f["id"], {})
        if "title" not in f and e.get("title"):
            f["title"] = e["title"]
        if "urgency" not in f and e.get("default_urgency"):
            f["urgency"] = e["default_urgency"]
        if "section" not in f and e.get("section"):
            f["section"] = e["section"]
        if "recommendation" not in f and e.get("recommendation"):
            f["recommendation"] = e["recommendation"]
        if "fix_hcl" not in f and e.get("fix_hcl"):
            f["fix_hcl"] = e["fix_hcl"]
        if "fix_disruption" not in f and e.get("fix_disruption"):
            f["fix_disruption"] = e["fix_disruption"]
        if "mitre" not in f and e.get("mitre"):
            f["mitre"] = list(e["mitre"])
        if "narrative" not in f:
            narr = _narrative_for_finding(f["id"], f.get("resource", ""), f.get("file", ""))
            if narr:
                f["narrative"] = narr
    return findings


# SARIF v2.1 supports a `taxonomies` array of structured taxonomy
# definitions (CWE, MITRE ATT&CK, etc.) plus per-rule `relationships`
# arrays linking each rule to the taxa it touches. Code Scanning
# consumers use these for semantic filtering ("show me all CWE-732
# findings"). The flat `cwe:CWE-732` tags emitted alongside are
# preserved for backward-compat with consumers that haven't moved off
# tag-only filtering.
_SARIF_TAXONOMY_DEFS: dict[str, dict] = {
    "CWE": {
        "name": "CWE",
        "guid": "F04C9E7C-2D60-49C8-B41A-9CCEB48F4E7E",
        "shortDescription": {"text": "Common Weakness Enumeration"},
        "informationUri": "https://cwe.mitre.org/",
        "downloadUri": "https://cwe.mitre.org/data/downloads.html",
        "isComprehensive": False,
    },
    "MITRE-ATT&CK": {
        "name": "MITRE-ATT&CK",
        "guid": "AAA0F22F-6F4C-4F2D-B14E-09EE2B5641D6",
        "shortDescription": {"text": "MITRE ATT&CK adversary tactics and techniques"},
        "informationUri": "https://attack.mitre.org/",
        "isComprehensive": False,
    },
    "MITRE-D3FEND": {
        "name": "MITRE-D3FEND",
        "guid": "A8FCD935-8523-4D04-95F7-7AAFC3E9A731",
        "shortDescription": {"text": "MITRE D3FEND defensive techniques"},
        "informationUri": "https://d3fend.mitre.org/",
        "isComprehensive": False,
    },
    "CIS": {
        "name": "CIS",
        "guid": "6F8B6E37-C9C3-4B1E-AD1E-4C8E5BE1F7B0",
        "shortDescription": {"text": "Center for Internet Security Benchmarks"},
        "informationUri": "https://www.cisecurity.org/cis-benchmarks/",
        "isComprehensive": False,
    },
}


def _sarif_taxonomies(entries: list[dict]) -> list[dict]:
    """Build the SARIF `taxonomies` array from every taxon referenced
    by any rule in `entries`. Each taxonomy gets its own block with
    `taxa` listing the specific IDs cited.

    Returns an empty list if no rule references any of the four
    supported taxonomies — keeps SARIF output minimal on small repos.
    """
    seen_taxa: dict[str, dict[str, dict]] = {
        "CWE": {}, "MITRE-ATT&CK": {}, "MITRE-D3FEND": {}, "CIS": {},
    }
    for entry in entries:
        for cid in (entry.get("cwe") or []):
            num = str(cid).removeprefix("CWE-")
            seen_taxa["CWE"][cid] = {
                "id": num,
                "name": cid,
                "shortDescription": {"text": cid},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{num}.html",
            }
        for tid in (entry.get("mitre") or []):
            seen_taxa["MITRE-ATT&CK"][str(tid)] = {
                "id": str(tid),
                "name": str(tid),
                "shortDescription": {"text": _mitre_technique_name(str(tid)) or str(tid)},
                "helpUri": f"https://attack.mitre.org/techniques/{str(tid).replace('.', '/')}/",
            }
        for did in (entry.get("d3fend") or []):
            seen_taxa["MITRE-D3FEND"][str(did)] = {
                "id": str(did),
                "name": str(did),
                "shortDescription": {"text": str(did)},
                "helpUri": f"https://d3fend.mitre.org/technique/{str(did)}/",
            }
        for cis in (entry.get("cis") or []):
            cid = str(cis)
            seen_taxa["CIS"][cid] = {
                "id": cid,
                "name": f"CIS {cid}",
                "shortDescription": {"text": f"CIS Benchmark control {cid}"},
            }

    out: list[dict] = []
    for tax_name, taxa_map in seen_taxa.items():
        if not taxa_map:
            continue
        defn = dict(_SARIF_TAXONOMY_DEFS[tax_name])
        defn["taxa"] = sorted(taxa_map.values(), key=lambda t: t["id"])
        out.append(defn)
    return out


def _sarif_rule_relationships(entry: dict) -> list[dict]:
    """Per-rule taxonomy references. Each entry produces one
    `relationships` element pointing at the matching taxon defined in
    the run's `taxonomies` block."""
    rels: list[dict] = []
    for cid in (entry.get("cwe") or []):
        rels.append({
            "target": {
                "id": str(cid).removeprefix("CWE-"),
                "name": str(cid),
                "toolComponent": {"name": "CWE", "guid": _SARIF_TAXONOMY_DEFS["CWE"]["guid"]},
            },
            "kinds": ["relevant"],
        })
    for tid in (entry.get("mitre") or []):
        rels.append({
            "target": {
                "id": str(tid),
                "name": str(tid),
                "toolComponent": {"name": "MITRE-ATT&CK", "guid": _SARIF_TAXONOMY_DEFS["MITRE-ATT&CK"]["guid"]},
            },
            "kinds": ["relevant"],
        })
    for did in (entry.get("d3fend") or []):
        rels.append({
            "target": {
                "id": str(did),
                "name": str(did),
                "toolComponent": {"name": "MITRE-D3FEND", "guid": _SARIF_TAXONOMY_DEFS["MITRE-D3FEND"]["guid"]},
            },
            # D3FEND is a defensive countermeasure — different relationship
            # kind so consumers can distinguish "this rule indicates the
            # named ATT&CK technique" from "this rule implements the named
            # D3FEND defence".
            "kinds": ["incomparable"],
        })
    for cis in (entry.get("cis") or []):
        rels.append({
            "target": {
                "id": str(cis),
                "name": f"CIS {cis}",
                "toolComponent": {"name": "CIS", "guid": _SARIF_TAXONOMY_DEFS["CIS"]["guid"]},
            },
            "kinds": ["relevant"],
        })
    return rels


def to_sarif(findings: list[dict], entries: list[dict]) -> dict:
    """Convert findings to SARIF v2.1.0 format with proper taxonomies."""
    rules = []
    rule_index = {}
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    severity_map = {
        "CRITICAL": "9.5",
        "HIGH": "7.5",
        "MEDIUM": "5.0",
        "LOW": "3.0",
        "INFO": "1.0",
    }
    for entry in entries:
        eid = entry["id"]
        if eid in rule_index:
            continue
        rule_index[eid] = len(rules)
        urgency = entry.get("default_urgency", "MEDIUM")
        recommendation = entry.get("recommendation") or entry.get("title", eid)
        rule_obj: dict = {
            "id": eid,
            "name": eid,
            "shortDescription": {"text": entry.get("title", eid)},
            "fullDescription": {"text": entry.get("title", eid)},
            "help": {
                "text": recommendation.strip() if isinstance(recommendation, str) else str(recommendation),
                "markdown": recommendation if isinstance(recommendation, str) else str(recommendation),
            },
            "helpUri": SARIF_HELP_URI_BASE.format(id=eid),
            "defaultConfiguration": {
                "level": level_map.get(urgency, "warning"),
            },
            "properties": {
                "tags": [
                    entry.get("section", "general"),
                    f"urgency:{urgency.lower()}",
                    f"blast-radius:{entry.get('blast_radius', 'single-resource')}",
                ]
                + [f"cis:{c}" for c in (entry.get("cis") or [])]
                + [f"mitre:{t}" for t in (entry.get("mitre") or [])]
                + [f"cwe:{c}" for c in (entry.get("cwe") or [])]
                + [f"d3fend:{d}" for d in (entry.get("d3fend") or [])],
                "precision": "high",
                "problem.severity": urgency.lower(),
                "security-severity": severity_map.get(urgency, "5.0"),
            },
        }
        # Taxonomy relationships — pointers into the run's `taxonomies`
        # block so consumers can semantically filter without parsing
        # the flat tag strings.
        rels = _sarif_rule_relationships(entry)
        if rels:
            rule_obj["relationships"] = rels
        rules.append(rule_obj)

    results = []
    for f in findings:
        # Defensive `.get` throughout — a synthetic or externally-supplied
        # finding missing `resource`/`file`/`line` must not KeyError and
        # abort the ENTIRE SARIF emit (SARIF has no per-result safety net).
        # `ruleIndex` is set ONLY when the rule is known: defaulting it to 0
        # mis-attributed an unknown-rule finding to rules[0] in GitHub Code
        # Scanning.
        fid = f.get("id", "UNKNOWN")
        result = {
            "ruleId": fid,
            "level": "warning",
            # SARIF message goes through `json.dumps` so quote escaping
            # is handled automatically — but a literal newline in the
            # resource name would break some lax consumers. Strip
            # control characters defensively.
            "message": {"text": _sarif_safe_text(f"Finding {fid} on {f.get('resource') or 'file'}")},
            "locations": [
                {
                    "physicalLocation": {
                        # Audit fix #19 — URI normalization. Windows
                        # paths emit backslashes; SARIF expects URI
                        # form. Use forward slashes uniformly.
                        "artifactLocation": {"uri": (f.get("file") or "").replace("\\", "/")},
                        "region": {"startLine": max(f.get("line") or 1, 1)},
                    }
                }
            ],
            "partialFingerprints": _sarif_fingerprint(f),
        }
        if fid in rule_index:
            idx = rule_index[fid]
            result["ruleIndex"] = idx
            result["level"] = rules[idx]["defaultConfiguration"]["level"]
        # KEV exploitability tag (R30.2). Surfaced at the per-result
        # level rather than per-rule so consumers can distinguish "this
        # specific finding hit a KEV-listed CWE" from "the rule could
        # theoretically map to KEV". GitHub Code Scanning surfaces these
        # tags in the result-detail panel.
        if f.get("kev"):
            result_props = result.setdefault("properties", {})
            result_tags = result_props.setdefault("tags", [])
            result_tags.append("exploitability:kev")
            if f.get("exploitability_score"):
                result_props["epss_score"] = f["exploitability_score"]
        # R30.17 — per-finding blast radius, populated when the engine
        # ran with --attack-graph. SARIF consumers (GitHub Code Scanning,
        # Sonatype, internal dashboards) can rank or filter by downstream
        # impact independently of urgency: a HIGH finding on a leaf
        # resource is less urgent on apply than a MEDIUM on a 30-downstream
        # VPC.
        if "blast_radius" in f and f["blast_radius"]:
            result_props = result.setdefault("properties", {})
            result_props["blastRadius"] = int(f["blast_radius"])
        results.append(result)

    taxonomies = _sarif_taxonomies(entries)
    run: dict = {
        "tool": {
            "driver": {
                "name": "tf-analyze",
                "version": "1.2.0",
                "informationUri": "https://github.com/ChrisAdkin8/tf-analyze",
                "rules": rules,
            }
        },
        "results": results,
    }
    # Only declare supportedTaxonomies + the taxonomies block when at
    # least one rule references one — keeps SARIF lean on small repos.
    if taxonomies:
        run["tool"]["driver"]["supportedTaxonomies"] = [
            {"name": t["name"], "guid": t["guid"]} for t in taxonomies
        ]
        run["taxonomies"] = taxonomies

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


# ---- adversarial scenario narratives ------------------------------------

_ATTACK_NARRATIVES: dict[str, str] = {
    "SEC-AWS-SSRF-001": (
        "An attacker exploiting a Server-Side Request Forgery (SSRF) vulnerability in any "
        "application running on {resource} can query the EC2 metadata endpoint "
        "(http://169.254.169.254/) and retrieve temporary IAM credentials without "
        "authentication — IMDSv1 requires no session token. "
        "This was the exact attack vector in the 2019 Capital One breach, where a WAF "
        "misconfiguration allowed an SSRF that exfiltrated 100M customer records via the "
        "instance's over-privileged role. "
        "Enforcing IMDSv2 (http_tokens = \"required\") breaks the chain because the "
        "attacker's request must first complete a PUT handshake that a server-side forged "
        "request cannot perform."
    ),
    "SEC-AWS-IAM-001": (
        "A wildcard Resource in the IAM policy attached to {resource} grants the declared "
        "actions against every AWS resource in the account — any credential theft, role "
        "assumption, or confused-deputy exploit immediately yields account-wide blast radius. "
        "In the 2019 Capital One breach a broad S3-read role attached to an EC2 instance "
        "was the reason 100M records could be exfiltrated after SSRF retrieved the role's "
        "STS token. "
        "Scope the Resource ARN to the specific bucket, table, or secret the workload needs."
    ),
    "SEC-AWS-IAM-002": (
        "{resource} grants the AdministratorAccess policy or equivalent wildcard, giving any "
        "principal bound to it full control over every AWS service and resource in the account. "
        "Compromise of a single workload using this role — via SSRF, code injection, or supply "
        "chain attack — yields immediate account takeover with no further privilege escalation "
        "required. "
        "Replace with a least-privilege policy scoped to the exact API calls and resource ARNs "
        "the workload uses."
    ),
    "SEC-GCP-IAM-001": (
        "The broad project-level role granted by {resource} gives any principal bound to it "
        "control over every resource in the GCP project — compute, storage, secrets, and IAM "
        "itself. "
        "An attacker who compromises a single workload service account inheriting this binding "
        "can pivot to exfiltrate Cloud SQL databases, read Secret Manager secrets, and create "
        "persistent backdoor service accounts, as demonstrated in multiple GCP supply-chain "
        "incidents. "
        "Replace with the narrowest resource-level role covering only the API surfaces the "
        "workload calls."
    ),
    "SEC-AWS-S3-001": (
        "Unencrypted data in {resource} is readable in plaintext by any AWS principal with "
        "s3:GetObject, including anyone who obtains temporary credentials via SSRF, stolen "
        "access keys, or a confused-deputy attack on an over-permissioned role. "
        "The 2017 Verizon and 2017 Accenture incidents both involved S3 buckets with sensitive "
        "data exposed without encryption, compounding the impact of misconfigured access controls. "
        "Apply SSE-KMS with a customer-managed key so data at rest requires key access in "
        "addition to bucket permissions."
    ),
    "SEC-AWS-SG-001": (
        "The security group {resource} accepts ingress from 0.0.0.0/0, making every instance "
        "in the group reachable from the public internet on the allowed port. "
        "This directly expands the attack surface for brute-force, CVE exploitation, and lateral "
        "movement — the 2020 SolarWinds attacker used internet-accessible management ports on "
        "internal hosts as persistence anchors. "
        "Restrict ingress to specific CIDR ranges, or use a bastion or SSM Session Manager to "
        "eliminate the public attack surface entirely."
    ),
    "SEC-AWS-RDS-001": (
        "Setting publicly_accessible = true on {resource} assigns the database a DNS name "
        "resolvable from the internet, exposing the database port to any network adversary. "
        "Combined with weak or default credentials, this is a trivially exploited attack path — "
        "internet-scanning tools like Shodan index publicly accessible RDS endpoints within "
        "minutes of provisioning. "
        "Place the instance in private subnets and use a VPC-peered bastion or AWS Systems "
        "Manager for administrative access."
    ),
    "SEC-AWS-CLOUDTRAIL-001": (
        "A single-region CloudTrail on {resource} creates detection blind spots in every other "
        "AWS region — an attacker deliberately operates in less-monitored regions to create IAM "
        "backdoors, launch instances, or establish data exfiltration pipelines. "
        "The 2020 SolarWinds-related AWS campaign specifically leveraged regions the victim had "
        "not enabled CloudTrail in, delaying detection by weeks. "
        "Enable is_multi_region_trail = true and include_global_service_events = true to capture "
        "all IAM and STS calls regardless of region."
    ),
    "SEC-GCP-GKE-NETWORK-POLICY-001": (
        "Without a network policy on {resource}, every pod in the cluster can reach every other "
        "pod on every port — there is no namespace isolation or default-deny. "
        "An attacker who compromises one container can scan and pivot to databases, metadata "
        "servers, and control-plane endpoints without any network-layer barrier, as demonstrated "
        "in the 2020 Tesla Kubernetes cryptomining incident where lateral movement from one "
        "compromised pod was unrestricted. "
        "Enable the built-in network policy provider and deploy default-deny egress policies in "
        "every workload namespace."
    ),
    "SEC-AZURE-RBAC-001": (
        "A subscription-scoped role assignment on {resource} grants the bound principal control "
        "over every resource in the Azure subscription — VMs, storage accounts, Key Vaults, and "
        "all other services. "
        "Compromise of the assigned identity via token theft, phishing, or service principal "
        "credential leak yields immediate lateral-movement capability across the entire "
        "subscription boundary, as seen in multiple Azure post-exploitation chains. "
        "Scope the assignment to the narrowest resource group or individual resource that "
        "satisfies the use case."
    ),
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": (
        "{resource} has a public IP via an access_config block, making it directly reachable "
        "from the internet and exposing any listening service to internet-scale scanners and "
        "exploit attempts. "
        "GCP instances with public IPs are routinely targeted within minutes of provisioning "
        "by automated credential-stuffing and exploitation bots, as documented in multiple GCP "
        "threat intelligence reports. "
        "Remove the access_config block and use Cloud NAT for outbound traffic; use "
        "Identity-Aware Proxy for authenticated inbound access."
    ),
    "SEC-AWS-KMS-001": (
        "KMS key rotation is disabled on {resource}, meaning that if the key material is ever "
        "compromised — via AWS account takeover, insider threat, or KMS API misuse — the "
        "compromise is permanent with no rotation event to remediate it. "
        "CIS AWS 2.8 requires annual key rotation as a compensating control for key exposure; "
        "disabling rotation violates PCI-DSS 3.6.4 for cryptographic keys protecting cardholder "
        "data. "
        "Enable enable_key_rotation = true; AWS rotates automatically and retains old material "
        "for decryption of previously encrypted data."
    ),
    "SEC-GCP-COMPUTE-SA-001": (
        "{resource} uses the default Compute Engine service account, which holds roles/editor "
        "project-wide — any workload code or attacker who gains code execution on this VM can "
        "read every bucket, modify every Cloud SQL database, and impersonate other service "
        "accounts. "
        "The default SA pattern was the root cause in several GCP privilege-escalation chains "
        "documented by Palo Alto Unit 42, where container escape led to project-wide compromise "
        "via the VM's inherited credentials. "
        "Bind a dedicated, narrowly scoped service account to every Compute instance."
    ),
    "SEC-HARDCODED-SECRET-001": (
        "A hardcoded credential in {file} is stored in version control history permanently — "
        "git filter-repo is required to fully purge it, and any fork or clone made before "
        "remediation retains the value. "
        "The 2022 Samsung source code leak and the 2021 Twitch leak both exposed hardcoded API "
        "keys that were immediately weaponized by threat actors monitoring public repos with "
        "automated credential-scanning tools. "
        "Rotate the credential immediately, replace it with a Secrets Manager or Vault reference, "
        "and add the pattern to a pre-commit hook to prevent recurrence."
    ),
    "SEC-GCP-SQL-PUBLIC-001": (
        "{resource} has ipv4_enabled = true, assigning the Cloud SQL instance a public IP "
        "reachable from the internet — even with authorized_networks set, a single misconfigured "
        "network rule or future change exposes the database to direct attack. "
        "Internet-exposed Cloud SQL instances are routinely targeted by automated "
        "credential-stuffing attacks, and any SQL injection in the connected application can be "
        "exploited without traversing VPC boundaries. "
        "Set ipv4_enabled = false and use Private Service Connect or private IP allocation for "
        "all database connectivity."
    ),
    "SEC-AWS-IAM-POLICY-001": (
        "{resource} grants `actions = [\"*\"]` — any AWS API call is permitted against the "
        "scoped resource set. Once an attacker holds credentials bound to this policy, the "
        "blast radius is whatever the resource list happens to be. The 2019 Capital One breach "
        "began with a wildcard-action role attached to a single EC2 instance; SSRF retrieved "
        "the role's STS token, and the wildcard then cleared every subsequent S3 list/get call. "
        "Enumerate the explicit minimum action set and validate with "
        "`aws iam simulate-principal-policy` before tightening."
    ),
    "SEC-AWS-IAM-POLICY-002": (
        "{resource} grants an `iam:*` wildcard, allowing the bound principal to create "
        "policies, attach them to itself, or rotate access keys for any user. This is a "
        "self-mutating identity — privilege escalation requires no separate exploit, just one "
        "credential leak. Internal red-team exercises consistently identify this single grant "
        "as the highest-yield foothold once initial access is achieved. "
        "Replace with the explicit IAM operations the workload genuinely needs (most apps need "
        "*none*)."
    ),
    "SEC-AWS-IAM-POLICY-004": (
        "{resource} attaches a policy whose `principals.identifiers = [\"*\"]` — every AWS "
        "account on the planet, plus AWS service principals, can invoke the granted actions. "
        "On an S3 bucket policy this means public reads/writes; on a KMS key policy it means "
        "any account can decrypt; on a Secrets Manager resource policy it means anyone can "
        "fetch the secret. The 2017 Accenture and 2019 Verizon Wireless leaks were both "
        "caused by exactly this shape on production buckets. "
        "Replace with a structured AWS account or service principal whitelist; if true public "
        "exposure is intentional, gate it behind explicit `Condition` keys and a "
        "`aws_s3_bucket_public_access_block` exception."
    ),
    "SEC-AWS-IAM-POLICY-005": (
        "A single statement on {resource} grants `actions = [\"*\"]` AND "
        "`resources = [\"*\"]` — equivalent to attaching `AdministratorAccess` but bypassing "
        "the org-level guardrails (SCPs, IAM Access Analyzer) that flag the named policy. "
        "Any compromise of the bound principal yields immediate full-account takeover; "
        "attacker pivot requires no further escalation. If true admin access is intentional "
        "this should be the AWS-managed policy attached by name so audit tooling sees it; "
        "otherwise, scope to the explicit minimum surface."
    ),
}


def _narrative_for_finding(
    rule_id: str,
    resource: str = "",
    file: str = "",
) -> str | None:
    """Return a formatted attack narrative for a rule ID, or None if unavailable."""
    template = _ATTACK_NARRATIVES.get(rule_id)
    if template is None:
        return None
    return template.format(
        resource=resource or rule_id,
        file=file or "unknown file",
    )


# ---- HTML output ---------------------------------------------------------

def _render_executive_view(
    findings: list[dict],
    entries: list[dict],
    graph: dict | None,
) -> str:
    """Render the Executive View tab body — findings reorganised by attack stage."""
    entry_map = {e["id"]: e for e in entries}

    # Build node membership sets from graph
    internet_set: set[str] = set()
    crown_set: set[str] = set()
    iam_net_set: set[str] = set()
    if graph:
        for n in graph.get("nodes", []):
            nid = n["id"]
            if n.get("internet_reachable"):
                internet_set.add(nid)
            if n.get("is_crown_jewel"):
                crown_set.add(nid)
            if n.get("type") in ("iam", "network"):
                iam_net_set.add(nid)

    # Classify each finding into a stage
    entry_points: list[dict] = []
    lateral_movement: list[dict] = []
    crown_jewels: list[dict] = []
    blind_spots: list[dict] = []
    for f in findings:
        res = f.get("resource", "")
        entry = entry_map.get(f["id"], {})
        section = entry.get("section", "")
        if section == "ops":
            blind_spots.append(f)
        elif res in crown_set:
            crown_jewels.append(f)
        elif res in internet_set:
            entry_points.append(f)
        elif res in iam_net_set:
            lateral_movement.append(f)
        else:
            blind_spots.append(f)  # unclassified → blind spots bucket

    def _stage_html(title: str, colour: str, prose: str, stage_findings: list[dict]) -> str:
        if not stage_findings:
            return f"<div style='margin-bottom:1.4em'><h3 style='color:{colour};margin-bottom:.3em'>{title}</h3><p style='color:#888;font-size:13px'>No findings in this stage.</p></div>"
        rows = []
        for f in stage_findings:
            entry = entry_map.get(f["id"], {})
            urgency = _effective_urgency(f, entry)
            urg_colour = {"CRITICAL": "#7b0000", "HIGH": "#b02a2a", "MEDIUM": "#b07800", "LOW": "#5a7a00", "INFO": "#4a6a8a"}.get(urgency, "#555")
            # Audit fix #1 — every engine-supplied field below is run
            # through `_h` (html.escape). `urgency` and `urg_colour` are
            # internal (urgency is one of CRITICAL/.../INFO; the colour
            # comes from a literal dict) so they're left as-is.
            rows.append(
                f"<li style='margin:.3em 0;font-size:13px'>"
                f"<span style='background:{urg_colour};color:#fff;padding:1px 7px;border-radius:3px;"
                f"font-size:11px;font-weight:700;margin-right:.5em'>{_h(urgency)}</span>"
                f"<b>{_h(f['id'])}</b> — {_h(entry.get('title',''))}"
                f"<span style='color:#888;margin-left:.5em'>{_h(f.get('resource',''))}</span>"
                f"<span style='color:#aaa;font-size:11px;margin-left:.5em'>{_h(f.get('file','').rsplit('/',2)[-1])}:{_h(str(f.get('line','')))}</span>"
                f"</li>"
            )
        rows_html = "\n".join(rows)
        # `title`, `prose`, and `colour` are literal strings from the
        # caller (the stage definitions are hard-coded). Still
        # defensive-escape title + prose because they could be
        # parameterised in the future.
        return (
            f"<div style='margin-bottom:1.8em'>"
            f"<h3 style='color:{colour};margin:.6em 0 .3em'>{_h(title)} "
            f"<span style='font-size:13px;font-weight:400;color:#666'>({len(stage_findings)} finding{'s' if len(stage_findings)!=1 else ''})</span></h3>"
            f"<p style='color:#555;font-size:13px;font-style:italic;margin-bottom:.6em'>{_h(prose)}</p>"
            f"<ul style='list-style:none;padding:0;margin:0'>{rows_html}</ul>"
            f"</div>"
        )

    cp_note = ""
    if graph and graph.get("critical_path"):
        path = graph["critical_path"]
        cp_note = (
            f"<div style='background:#fff3f3;border-left:4px solid #c0392b;padding:.7em 1em;"
            f"border-radius:0 6px 6px 0;margin-bottom:1.4em;font-size:13px'>"
            f"<b style='color:#c0392b'>Critical Attack Path detected</b> — "
            f"the shortest route from the internet to a crown jewel passes through "
            f"<b>{len(path)}</b> resource{'s' if len(path)!=1 else ''}: "
            f"{' → '.join(f'<code>{_h(r)}</code>' for r in path)}. "
            f"Findings on these resources are promoted one urgency tier."
            f"</div>"
        )

    stage1 = _stage_html(
        "&#9889; Stage 1 — Entry Points", "#d35400",
        "Internet-reachable resources with active findings. These are where an attacker gains initial access.",
        entry_points,
    )
    stage2 = _stage_html(
        "&#8596; Stage 2 — Lateral Movement", "#6c5ce7",
        "IAM roles, policies, and network resources with findings. A foothold in Stage 1 can pivot here.",
        lateral_movement,
    )
    stage3 = _stage_html(
        "&#128142; Stage 3 — Crown Jewels at Risk", "#6b0000",
        "Databases, secret stores, and encryption keys with findings. These are the targets.",
        crown_jewels,
    )
    stage4 = _stage_html(
        "&#128263; Stage 4 — Blind Spots", "#555",
        "Logging, monitoring, and operational findings. An attacker exploiting earlier stages would likely go undetected.",
        blind_spots,
    )

    return cp_note + stage1 + stage2 + stage3 + stage4


# ---- Feature 2: Safe-to-Fix Disruption Classification ------------------
# `_VALID_FIX_DISRUPTIONS` is re-imported from `_catalog.py` (used by
# `validate_catalog_entry` at the catalogue seam).

_FIX_DISRUPTION_LABELS = {
    "none": ("&#9989; Non-disruptive", "#27ae60"),
    "plan_required": ("&#9888;&#65039; Plan required", "#c27a00"),
    "forces_replacement": ("&#128293; Forces replacement", "#b02a2a"),
}


def _disruption_badge(disruption: str) -> str:
    label, color = _FIX_DISRUPTION_LABELS.get(disruption, ("", ""))
    if not label:
        return ""
    return (
        f"<span style='background:{color};color:#fff;padding:1px 7px;"
        f"border-radius:3px;font-size:11px;font-weight:600;"
        f"margin-left:6px'>{label}</span>"
    )


# ---- Feature 3: Compliance Gap Report ----------------------------------

_CIS_FRAMEWORK_PREFIXES = [
    ("SEC-AWS", "CIS AWS Foundations Benchmark v3.0"),
    ("ROB-AWS", "CIS AWS Foundations Benchmark v3.0"),
    ("SEC-GCP", "CIS GCP Foundations Benchmark v4.0"),
    ("ROB-GCP", "CIS GCP Foundations Benchmark v4.0"),
    ("SEC-AZURE", "CIS Azure Foundations Benchmark v2.0"),
    ("ROB-AZURE", "CIS Azure Foundations Benchmark v2.0"),
]


def _infer_cis_framework(rule_id: str) -> str:
    for prefix, fw in _CIS_FRAMEWORK_PREFIXES:
        if rule_id.startswith(prefix):
            return fw
    return "Other"


def _compliance_gap_report(
    findings: list[dict],
    entries: list[dict],
    framework: str = "cis",
) -> dict:
    """Map compliance controls against fired findings; return {framework: [control_dicts]}.

    Each control dict: {control, rules, status ('PASS'|'FAIL'), failed_rules}.
    Controls with no catalogue coverage are omitted (NOT-ASSESSABLE).

    framework: 'cis' (default), 'pci_dss', 'soc2', or 'all' (combines all three).
    """
    fired_ids = {f["id"] for f in findings}
    control_map: dict[str, dict] = {}

    want_cis    = framework in ("cis", "all")
    want_pci    = framework in ("pci_dss", "all")
    want_soc2   = framework in ("soc2", "all")
    want_owasp  = framework in ("owasp_iac", "all")
    # R30.1 — multi-framework taxonomy sweep
    want_csf    = framework in ("nist_csf", "all")
    want_853    = framework in ("nist_800_53", "all")
    want_ccm    = framework in ("csa_ccm", "all")
    want_slsa   = framework in ("slsa", "all")
    # OWASP sub-modes — each filters against the namespaced `owasp:`
    # field by item prefix. `all` includes every prefix.
    want_owasp_top10 = framework in ("owasp_top10", "all")
    want_owasp_api   = framework in ("owasp_api", "all")
    want_owasp_cicd  = framework in ("owasp_cicd", "all")
    want_owasp_llm   = framework in ("owasp_llm", "all")
    want_owasp_k8s   = framework in ("owasp_k8s", "all")
    want_owasp_asvs  = framework in ("owasp_asvs", "all")

    def _record(framework_name: str, control: str, eid: str) -> None:
        key = f"{framework_name}::{control}"
        if key not in control_map:
            control_map[key] = {
                "framework": framework_name, "control": str(control),
                "rules": [], "failed_rules": [], "status": "PASS",
            }
        control_map[key]["rules"].append(eid)

    for entry in entries:
        eid = entry.get("id", "")

        if want_cis:
            cis_list = entry.get("cis", [])
            if not isinstance(cis_list, list):
                cis_list = [cis_list] if cis_list else []
            fw_name = _infer_cis_framework(eid)
            for ctrl in cis_list:
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

        if want_pci:
            pci_list = entry.get("pci_dss", [])
            if not isinstance(pci_list, list):
                pci_list = [pci_list] if pci_list else []
            for ctrl in pci_list:
                fw_name = "PCI-DSS v4.0"
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

        if want_soc2:
            soc2_list = entry.get("soc2_cc", [])
            if not isinstance(soc2_list, list):
                soc2_list = [soc2_list] if soc2_list else []
            for ctrl in soc2_list:
                fw_name = "SOC2 Trust Services Criteria"
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

        if want_owasp:
            owasp_list = entry.get("owasp_iac", [])
            if not isinstance(owasp_list, list):
                owasp_list = [owasp_list] if owasp_list else []
            for ctrl in owasp_list:
                fw_name = "OWASP IaC Cheat Sheet"
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

        # ---- R30.1 multi-framework taxonomy dispatch ----
        if want_csf:
            for ctrl in entry.get("nist_csf", []) or []:
                if isinstance(ctrl, str):
                    _record("NIST CSF 2.0", ctrl, eid)
        if want_853:
            for ctrl in entry.get("nist_800_53", []) or []:
                if isinstance(ctrl, str):
                    _record("NIST SP 800-53 Rev. 5", ctrl, eid)
        if want_ccm:
            for ctrl in entry.get("csa_ccm", []) or []:
                if isinstance(ctrl, str):
                    _record("CSA CCM v4", ctrl, eid)
        if want_slsa:
            for ctrl in entry.get("slsa", []) or []:
                if isinstance(ctrl, str):
                    _record("SLSA v1.0", ctrl, eid)
        # OWASP sub-modes — filter the namespaced `owasp:` field by
        # item prefix so a single field powers five separate frameworks.
        owasp_namespaced = entry.get("owasp", []) or []
        if isinstance(owasp_namespaced, list):
            for ctrl in owasp_namespaced:
                if not isinstance(ctrl, str):
                    continue
                if want_owasp_top10 and re.fullmatch(r"A(?:0[1-9]|10)", ctrl):
                    _record("OWASP Top 10 (2021)", ctrl, eid)
                elif want_owasp_api and re.fullmatch(r"API(?:0[1-9]|10)", ctrl):
                    _record("OWASP API Top 10 (2023)", ctrl, eid)
                elif want_owasp_cicd and ctrl.startswith("CICD-SEC-"):
                    _record("OWASP CICD Top 10", ctrl, eid)
                elif want_owasp_llm and re.fullmatch(r"LLM(?:0[1-9]|10)", ctrl):
                    _record("OWASP LLM Top 10 (2025)", ctrl, eid)
                elif want_owasp_k8s and re.fullmatch(r"K(?:0[1-9]|10)", ctrl):
                    _record("OWASP Kubernetes Top 10", ctrl, eid)
                elif want_owasp_asvs and ctrl.startswith("ASVS-"):
                    _record("OWASP ASVS v4", ctrl, eid)

    for item in control_map.values():
        failed = [r for r in item["rules"] if r in fired_ids]
        item["failed_rules"] = failed
        item["status"] = "FAIL" if failed else "PASS"

    by_fw: dict[str, list[dict]] = {}
    for item in control_map.values():
        by_fw.setdefault(item["framework"], []).append(item)

    def _ctrl_sort_key(c: dict) -> list:
        # Compliance control IDs are dotted/hyphenated mixes like "1.2.3",
        # "AC-2.a", "CC6.1" — but the OWASP IaC cheat sheet uses prose
        # labels like "Develop and Distribute / Secrets Detection". Split
        # on /, ., - so prose-shaped labels still sort by their lexical
        # parts, then wrap each part as (sort_class, value) so int vs.
        # str comparisons never raise: 0=numeric (int-sorted), 1=alpha
        # (str-sorted). Numeric parts sort before alpha ones at the same
        # position, which matches how humans read control IDs.
        parts = re.split(r'[./\-]', c["control"])
        return [(0, int(x)) if x.isdigit() else (1, x.strip()) for x in parts]

    for fw in by_fw:
        by_fw[fw].sort(key=_ctrl_sort_key)

    return by_fw


# MITRE ATT&CK reference data + helpers live in `scripts/_mitre.py`.
# Module-level aliases here preserve the legacy `_MITRE_*` private
# names for code inside this file (no behavioural change) and let
# external consumers (drift-check script, tests) import from either
# location.
from _mitre import (
    MITRE_TECHNIQUE_INFO as _MITRE_TECHNIQUE_INFO,
    MITRE_TACTIC_ORDER as _MITRE_TACTIC_ORDER,
    mitre_technique_name as _mitre_technique_name,
    mitre_technique_tactics as _mitre_technique_tactics,
)


def _render_mitre(findings: list[dict], entries: list[dict],
                  tactic_filter: str | None = None) -> str:
    """Render findings grouped by ATT&CK tactic → technique.

    Output structure (matches how SOC analysts read ATT&CK):

        ## MITRE ATT&CK Coverage  (vN, ATT&CK release)

        ### Initial Access
          T1190 — Exploit Public-Facing Application  (3 findings)
            [HIGH] SEC-AWS-APIGW-001 ...
        ### Defense Evasion
          T1562.008 — Impair Defenses: Disable or Modify Cloud Logs  (5 findings)
            ...

    Findings whose rule has no `mitre:` mapping are grouped under a
    final '(unmapped)' tactic so coverage gaps stay visible.

    `tactic_filter` (from --mitre-tactic) restricts output to one tactic;
    case-insensitive, hyphen/space tolerant ('initial-access' == 'Initial Access').
    """
    entry_map = {e["id"]: e for e in entries}

    # Bucket findings by (tactic, technique) — a finding can appear in
    # multiple tactics if its technique is multi-tactic (e.g. T1078.004
    # is both Initial Access and Persistence).
    by_tactic: dict[str, dict[str, list[dict]]] = {}
    for f in findings:
        e = entry_map.get(f["id"], {})
        techs = e.get("mitre") or []
        if not techs:
            by_tactic.setdefault("(unmapped)", {}).setdefault("(unmapped)", []).append(f)
            continue
        for t in techs:
            for tactic in _mitre_technique_tactics(str(t)):
                by_tactic.setdefault(tactic, {}).setdefault(str(t), []).append(f)

    if tactic_filter:
        wanted = re.sub(r"[-_ ]", "", tactic_filter).lower()
        by_tactic = {
            k: v for k, v in by_tactic.items()
            if re.sub(r"[-_ ]", "", k).lower() == wanted
        }

    # Audit fix #11 — sort uses the module-level rank.
    URGENCY_RANK = URGENCY_RANK_ASCENDING
    out: list[str] = [
        f"## MITRE ATT&CK Coverage  (pinned to ATT&CK {MITRE_ATTACK_VERSION})",
        "",
    ]
    if not by_tactic:
        out.append("(no findings)")
        return "\n".join(out)

    # Render in canonical tactic order; unknown / synthetic tactics
    # (Other, (unmapped)) sort to the end.
    def _tactic_sort_key(name: str) -> tuple[int, str]:
        try:
            return (_MITRE_TACTIC_ORDER.index(name), name)
        except ValueError:
            return (len(_MITRE_TACTIC_ORDER) + (1 if name == "(unmapped)" else 0), name)

    for tactic in sorted(by_tactic, key=_tactic_sort_key):
        techs_in_tactic = by_tactic[tactic]
        # Total findings under this tactic (deduped by file:line:id)
        total = len({(f["id"], f.get("file"), f.get("line"))
                     for group in techs_in_tactic.values() for f in group})
        out.append(f"### {tactic}  ({total} finding{'s' if total != 1 else ''})")
        for tech in sorted(techs_in_tactic):
            group = techs_in_tactic[tech]
            name = _mitre_technique_name(tech)
            label = f"{tech} — {name}" if name else tech
            out.append(f"  {label}  ({len(group)} finding{'s' if len(group) != 1 else ''})")
            for f in sorted(
                group,
                key=lambda x: (
                    URGENCY_RANK.get(entry_map.get(x["id"], {}).get("default_urgency", "INFO"), 9),
                    x["id"],
                    x.get("file", ""),
                    x.get("line", 0),
                ),
            ):
                urg = entry_map.get(f["id"], {}).get("default_urgency", "?")
                out.append(
                    f"    [{urg}] {f['id']}  {f.get('file','')}:{f.get('line','?')}  "
                    f"{f.get('resource','')}"
                )
        out.append("")
    return "\n".join(out)


_PR_SUMMARY_GRADE_EMOJI: dict[str, str] = {
    "A": "🟢", "B": "🔵", "B-": "🔵", "C": "🟡", "D": "🟠", "F": "🔴",
}


def _append_attack_graph_block(parts: list[str], attack_graph: dict) -> None:
    """Append a `<details>`-collapsed Mermaid attack-graph block to
    ``parts``. Used by ``_render_pr_summary`` in two places (clean-repo
    path + findings path); kept in one helper so the visible shape
    stays consistent.
    """
    nodes = attack_graph.get("nodes", [])
    edges = attack_graph.get("edges", [])
    crown = sum(1 for n in nodes if n.get("is_crown_jewel"))
    parts.append(
        f"<details><summary>🛤 Attack graph: "
        f"{len(nodes)} nodes · {len(edges)} edges · {crown} crown jewels</summary>"
    )
    parts.append("")
    parts.append(graph_to_mermaid(attack_graph))
    parts.append("")
    parts.append("</details>")


def _append_compliance_block(parts: list[str], compliance: dict) -> None:
    """Append a collapsible compliance gap report block to `parts`.

    R31.8 (issue #12): factored out so both the clean-repo path and
    the findings-present path render the same compliance shape. The
    `compliance` dict comes from the engine's `--compliance` pass and
    has the shape:

        {"<framework>": [{"control": "…", "status": "PASS"|"FAIL",
                          "rules": [...], "failed_rules": [...]}, ...]}

    Failures sort to the top of each control list; rules that fired
    are bolded so reviewers spot them without expanding more sections.
    """
    for fw in sorted(compliance):
        controls = compliance[fw] or []
        if not controls:
            continue
        total = len(controls)
        passed = sum(1 for c in controls if c.get("status") == "PASS")
        failed = total - passed
        pct = int(100 * passed / total) if total else 0
        indicator = "🟢" if pct >= 80 else ("🟡" if pct >= 50 else "🔴")
        parts.append(
            f"<details><summary>📋 Compliance ({fw}): "
            f"{indicator} {passed}/{total} PASS · {failed} FAIL</summary>"
        )
        parts.append("")
        parts.append("| Control | Status | Mapped rules |")
        parts.append("|---|---|---|")
        ordered = sorted(
            controls,
            key=lambda c: (0 if c.get("status") == "FAIL" else 1, c.get("control", "")),
        )
        for ctrl in ordered:
            status_emoji = "❌ FAIL" if ctrl.get("status") == "FAIL" else "✅ PASS"
            rules = ctrl.get("rules") or []
            failed_rules = set(ctrl.get("failed_rules") or [])
            rule_cells = []
            for r in rules:
                link = f"[`{r}`]({RULE_DOCS_URL_BASE.format(id=r)})"
                rule_cells.append(f"**{link}**" if r in failed_rules else link)
            rule_str = ", ".join(rule_cells) or "—"
            parts.append(
                f"| `{ctrl.get('control', '?')}` | {status_emoji} | {rule_str} |"
            )
        parts.append("")
        parts.append("</details>")
        parts.append("")


def _render_pr_summary_minimal_fallback(summary: dict, *, reason: str = "") -> str:
    """Tiny pr-summary fallback shape — counts table only.

    Used by the public ``_render_pr_summary`` wrapper when the full
    renderer raises (R31.8 — issue #13). Producing a non-empty
    Markdown string here means the GitHub Action's downstream
    github-script step doesn't have to make up a fallback of its own
    — engine output is always renderable.
    """
    score = summary.get("score", 0)
    grade = summary.get("grade", "?")
    counts = summary.get("counts", {})
    lines = [
        f"## tf-analyze: {score} ({grade})",
        "",
        "| Urgency | Count |",
        "|---------|------:|",
        f"| 🚨 CRITICAL | {counts.get('CRITICAL', 0)} |",
        f"| ⚠️ HIGH | {counts.get('HIGH', 0)} |",
        f"| 💡 MEDIUM | {counts.get('MEDIUM', 0)} |",
        f"| ℹ️ LOW | {counts.get('LOW', 0)} |",
        "",
    ]
    if reason:
        # Make the degraded shape visible to humans reading the PR
        # comment, so a renderer regression doesn't pass for "looks
        # normal, just terser".
        lines.append(f"<sub>⚠️ pr-summary fallback — renderer error: {reason}</sub>")
    return "\n".join(lines) + "\n"


def _render_pr_summary(
    findings: list[dict],
    entries: list[dict],
    summary: dict,
    *,
    attack_graph: dict | None = None,
    centrality: list[dict] | dict | None = None,
    compliance: dict | None = None,
) -> str:
    """Public entry point — never raises.

    R31.8 (issue #13): the real renderer (`_render_pr_summary_impl`)
    used to crash silently with `AttributeError: 'list' object has no
    attribute 'get'` when called from `detect.py` with the
    `_score_fix_centrality` list shape — the engine then wrote an
    empty pr-summary.md and the downstream GitHub Action's
    github-script step had to make up its own fallback. This wrapper
    catches any exception, emits a `::warning::` annotation, and
    returns the minimal fallback shape so the engine never silently
    produces empty pr-summary output.
    """
    try:
        return _render_pr_summary_impl(
            findings, entries, summary,
            attack_graph=attack_graph,
            centrality=centrality,
            compliance=compliance,
        )
    except Exception as exc:  # noqa: BLE001 — broad on purpose; this IS the safety net
        import sys
        sys.stderr.write(
            f"::warning::tf-analyze: pr-summary rendering failed "
            f"({type(exc).__name__}: {exc}); emitting minimal fallback. "
            f"Please file an issue at "
            f"https://github.com/ChrisAdkin8/tf-analyze/issues "
            f"with the engine inputs that triggered this.\n"
        )
        return _render_pr_summary_minimal_fallback(
            summary, reason=f"{type(exc).__name__}: {exc}"
        )


def _render_pr_summary_impl(
    findings: list[dict],
    entries: list[dict],
    summary: dict,
    *,
    attack_graph: dict | None = None,
    centrality: list[dict] | dict | None = None,
    compliance: dict | None = None,
) -> str:
    """Concise GitHub-flavoured Markdown sized for PR descriptions and
    PR-bot summary comments.

    Layout:

      ## tf-analyze: {score} ({grade})  {emoji}
      <one-line counts>

      **Top 3 findings** (by urgency × centrality)
      | … |

      **Top fix** (highest centrality with `fix_hcl`)
      ```hcl …```

      <details><summary>Attack graph (N nodes / M edges)</summary>
      ```mermaid …```
      </details>

      <details><summary>📋 Compliance gap report (framework)</summary>
      | Control | Status | Mapped Rules |
      …
      </details>

    Distinct from `--format text` (verbose, CLI-shaped) and `--format
    json` (machine-shaped). Designed to be pasted directly into a PR
    description or appended to the GitHub Action's comment summaryBody.

    Never call this directly — go through `_render_pr_summary` so the
    safety-net wrapper catches any renderer regression.
    """
    score = summary.get("score", 0)
    grade = summary.get("grade", "?")
    counts = summary.get("counts", {})
    emoji = _PR_SUMMARY_GRADE_EMOJI.get(grade, "")
    entry_map = {e["id"]: e for e in entries}

    parts: list[str] = []
    parts.append(f"## tf-analyze: {score} ({grade}) {emoji}".rstrip())

    # One-line headline counts.
    counts_line = " · ".join(
        f"**{counts.get(tier, 0)}** {tier}"
        for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    parts.append(f"{counts_line} · {len(findings)} total")
    parts.append("")

    if not findings:
        parts.append("✅ Clean — no findings at default scoring tiers.")
        # Even on a clean repo, surface the attack graph if one was
        # built — the picture itself is shareable content.
        if attack_graph and attack_graph.get("edges"):
            parts.append("")
            _append_attack_graph_block(parts, attack_graph)
        # Compliance gap report — even on a clean repo this is the
        # positive signal users want to see ("N/N controls PASS").
        if compliance:
            parts.append("")
            _append_compliance_block(parts, compliance)
        parts.append("")
        parts.append(
            "<sub>🛡 Generated by [tf-analyze]"
            "(https://github.com/ChrisAdkin8/tf-analyze) · "
            "[full rule reference](https://chrisadkin8.github.io/tf-analyze/rules/)</sub>"
        )
        return "\n".join(parts) + "\n"

    # Rank findings by urgency × centrality. Centrality may be absent
    # (graph wasn't built); treat missing as 0 so urgency dominates.
    # Audit fix #11 — share the single source of truth at module top.
    URG_RANK = URGENCY_RANK_ASCENDING

    # R31.8 (issue #13): `centrality` comes from `_score_fix_centrality`
    # which returns `list[dict]` — one row per finding-resource with an
    # `impact` score (`crowns_blocked × 10 + critical-path/internet
    # bonuses`). Older callers passed a `{file:line: float}` dict; we
    # accept both shapes and produce a single `{finding_id: impact}`
    # lookup. Without this normalisation, `cent.get(...)` raised
    # `AttributeError: 'list' object has no attribute 'get'` and the
    # whole renderer fell back to the safety-net wrapper above.
    cent_impact: dict[str, float] = {}
    if isinstance(centrality, list):
        for c in centrality:
            fid = c.get("finding_id", "")
            if fid:
                cent_impact[fid] = float(c.get("impact", 0))
    elif isinstance(centrality, dict):
        # Legacy {file:line: score} dict, kept for back-compat with any
        # external caller that still hands the older shape.
        cent_impact = {}  # populated lazily inside _rank_key
        _legacy_cent = centrality
    else:
        _legacy_cent = {}

    def _rank_key(f: dict) -> tuple:
        urg = entry_map.get(f["id"], {}).get("default_urgency", "INFO")
        # Higher centrality → smaller key value (sort ascending).
        if cent_impact:
            c = -cent_impact.get(f["id"], 0.0)
        else:
            c = -_legacy_cent.get(f"{f.get('file','')}:{f.get('line',0)}", 0.0) \
                if isinstance(centrality, dict) else 0.0
        return (URG_RANK.get(urg, 9), c, f["id"])

    ranked = sorted(findings, key=_rank_key)

    # Top-3 findings table.
    parts.append("### Top findings")
    parts.append("")
    parts.append("| Urgency | Rule | Location |")
    parts.append("|---|---|---|")
    for f in ranked[:3]:
        rid = f["id"]
        urg = entry_map.get(rid, {}).get("default_urgency", "?")
        title = entry_map.get(rid, {}).get("title", "")
        loc = f"`{f.get('file','?')}:{f.get('line','?')}`"
        # 🔥 KEV badge (R30.2) when the rule's CWE intersects CISA's
        # Known Exploited Vulnerabilities. Prepended to the urgency
        # cell so the visual landmark lands at column 1.
        kev_badge = "🔥 " if f.get("kev") else ""
        # Link rule ID to the canonical docs page so reviewers can
        # one-click for full rationale.
        rule_link = f"[`{rid}`]({RULE_DOCS_URL_BASE.format(id=rid)}) — {title}"
        parts.append(f"| {kev_badge}**{urg}** | {rule_link} | {loc} |")
    if len(ranked) > 3:
        parts.append("")
        parts.append(
            f"<sub>+{len(ranked) - 3} more — full output: "
            f"`detect.py --target . --format text`</sub>"
        )
    parts.append("")

    # R30.18 — Blast-radius callout. Surfaces high-blast findings as a
    # dedicated SRE/oncall block: "even before scoring, these are the
    # ones whose merge would touch the most downstream resources". Only
    # rendered when the engine ran with --attack-graph; threshold is
    # the same `_BLAST_UPLIFT_SMALL` constant the LSP uses (5+) so the
    # two surfaces agree on what counts as "high blast".
    high_blast = [
        f for f in ranked
        if int(f.get("blast_radius") or 0) >= 5
    ]
    if high_blast:
        parts.append("### 🌊 High blast radius — review on-call impact")
        parts.append("")
        parts.append(
            "Findings on resources whose destruction or recreation "
            "would cascade to many dependents. Treat as high-care-on-apply."
        )
        parts.append("")
        parts.append("| Downstream | Rule | Resource |")
        parts.append("|---:|---|---|")
        for f in high_blast[:5]:
            rid = f["id"]
            br = int(f.get("blast_radius") or 0)
            resource = f.get("resource") or f.get("file", "?")
            rule_link = f"[`{rid}`]({RULE_DOCS_URL_BASE.format(id=rid)})"
            parts.append(f"| **{br}** | {rule_link} | `{resource}` |")
        if len(high_blast) > 5:
            parts.append("")
            parts.append(
                f"<sub>+{len(high_blast) - 5} more — full table in "
                f"`--format json` `blast_radius` block</sub>"
            )
        parts.append("")

    # Top fix — first ranked finding whose catalogue entry carries a fix_hcl.
    top_fix = next(
        (f for f in ranked
         if (entry_map.get(f["id"], {}).get("fix_hcl") or "").strip()),
        None,
    )
    if top_fix:
        rid = top_fix["id"]
        fix = entry_map[rid]["fix_hcl"].strip()
        # Truncate to keep the PR comment readable; full fix is on the docs page.
        if fix.count("\n") > 12:
            fix = "\n".join(fix.splitlines()[:12]) + "\n  # …"
        disruption = entry_map[rid].get("fix_disruption", "")
        disruption_note = (
            f" *(`{disruption}`)*" if disruption else ""
        )
        parts.append(f"### Top fix — {rid}{disruption_note}")
        parts.append("")
        parts.append("```hcl")
        parts.append(fix)
        parts.append("```")
        parts.append("")

    # Attack graph (collapsed). Only emit when the graph was built and
    # has at least one edge — an empty graph in a PR comment is noise.
    if attack_graph and attack_graph.get("edges"):
        _append_attack_graph_block(parts, attack_graph)
        parts.append("")

    # R31.8 (issue #12): compliance gap report, collapsed by default.
    # Only rendered when `--compliance-framework <name>` was passed
    # (the engine then populates the `compliance` dict). This was the
    # missing piece that left the engine-rendered comment silently
    # incomplete vs. what `compliance-framework:` set on the action
    # led users to expect.
    if compliance:
        _append_compliance_block(parts, compliance)

    parts.append(
        "<sub>🛡 Generated by [tf-analyze]"
        "(https://github.com/ChrisAdkin8/tf-analyze) · "
        "[full rule reference](https://chrisadkin8.github.io/tf-analyze/rules/)</sub>"
    )
    return "\n".join(parts) + "\n"


def _render_compliance_text(by_fw: dict) -> str:
    lines: list[str] = [
        "## Compliance Gap Report",
        "",
        f"Per-rule docs: {RULE_DOCS_URL_BASE.format(id='<RULE-ID>')}",
        "(every rule ID below is a URL slug — append `.html` for the page)",
        "",
    ]
    for fw in sorted(by_fw):
        controls = by_fw[fw]
        total = len(controls)
        passed = sum(1 for c in controls if c["status"] == "PASS")
        failed = total - passed
        lines.append(f"### {fw}")
        lines.append(f"Coverage: {passed}/{total} PASS, {failed} FAIL")
        lines.append("")
        # Auto-size the Control column to the widest label in this
        # framework. Numeric IDs (`1.2.3`, `CC6.1`) need ~14 cols; the
        # OWASP IaC cheat sheet uses prose labels (`Develop and
        # Distribute / Secrets Detection`) that are 30-50 cols. Pad
        # at least 14 so existing CIS/PCI/SOC2 layouts don't change.
        ctrl_w = max(14, max((len(c["control"]) for c in controls), default=14) + 2)
        lines.append(f"{'Control':<{ctrl_w}}{'Status':<10}Rules")
        lines.append("-" * (ctrl_w + 60))
        for ctrl in controls:
            rules_str = ", ".join(ctrl["rules"])
            fail_str = (
                f"  [FAIL: {', '.join(ctrl['failed_rules'])}]"
                if ctrl["failed_rules"] else ""
            )
            lines.append(
                f"{ctrl['control']:<{ctrl_w}}{ctrl['status']:<10}{rules_str}{fail_str}"
            )
            # For each failed rule, print the docs URL on its own line.
            # Terminals auto-link these; users can click to read the
            # explanation, why-it-fired, and fix without leaving the
            # CI log.
            for r in ctrl["failed_rules"]:
                lines.append(f"{'':<{ctrl_w + 10}}↳ {RULE_DOCS_URL_BASE.format(id=r)}")
        lines.append("")
    return "\n".join(lines)


def _render_compliance_html(by_fw: dict) -> str:
    sections: list[str] = []
    for fw in sorted(by_fw):
        controls = by_fw[fw]
        total = len(controls)
        passed = sum(1 for c in controls if c["status"] == "PASS")
        failed = total - passed
        pct = int(100 * passed / total) if total else 0
        bar_color = "#27ae60" if pct >= 80 else ("#c27a00" if pct >= 50 else "#b02a2a")
        rows: list[str] = []
        for ctrl in controls:
            sbadge = (
                "<span style='background:#27ae60;color:#fff;padding:1px 8px;"
                "border-radius:3px;font-size:11px;font-weight:600'>PASS</span>"
                if ctrl["status"] == "PASS" else
                "<span style='background:#b02a2a;color:#fff;padding:1px 8px;"
                "border-radius:3px;font-size:11px;font-weight:600'>FAIL</span>"
            )
            def _rule_link(r: str) -> str:
                url = RULE_DOCS_URL_BASE.format(id=r)
                return (
                    f'<a href="{url}" target="_blank" rel="noopener" '
                    f'title="Open rule documentation"><code>{r}</code></a>'
                )
            rules_html = ", ".join(_rule_link(r) for r in ctrl["rules"])
            fail_html = ""
            if ctrl["failed_rules"]:
                fail_html = (
                    " <span style='color:#b02a2a'>("
                    + ", ".join(_rule_link(r) for r in ctrl["failed_rules"])
                    + " fired)</span>"
                )
            rows.append(
                f"<tr><td style='font-family:monospace'>{_h(str(ctrl['control']))}</td>"
                f"<td>{sbadge}</td>"
                f"<td>{rules_html}{fail_html}</td></tr>"
            )
        sections.append(
            f"<h3>{_h(str(fw))}</h3>"
            f"<p style='color:#555;font-size:13px'>"
            f"{passed}/{total} controls PASS ({pct}%) — {failed} FAIL</p>"
            f"<div style='background:#eee;border-radius:4px;height:8px;margin-bottom:.8em'>"
            f"<div style='background:{bar_color};width:{pct}%;height:8px;border-radius:4px'>"
            f"</div></div>"
            f"<table class='locs'>"
            f"<thead><tr><th>Control</th><th>Status</th><th>Mapped Rules</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )
    return (
        "<h2 style='margin-top:.5em'>CIS Compliance Gap Report</h2>"
        "<p style='color:#555;font-size:13px;margin-bottom:.8em'>"
        "Controls derived from catalogue <code>cis:</code> fields. "
        "PASS = no finding fired. FAIL = at least one finding fired. "
        "Controls without catalogue coverage are NOT-ASSESSABLE and omitted.</p>"
        + "".join(sections)
    )


def _compliance_to_oscal(by_fw: dict, target_dir: str = "") -> dict:
    """Produce a minimal OSCAL Assessment Results JSON structure."""
    import datetime as _dt
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings_oscal: list[dict] = []
    for fw, controls in sorted(by_fw.items()):
        for ctrl in controls:
            findings_oscal.append({
                "control-id": ctrl["control"],
                "framework": fw,
                "status": ctrl["status"].lower(),
                "related-observations": [
                    {"observation-uuid": r} for r in ctrl["failed_rules"]
                ],
            })
    return {
        "assessment-results": {
            "uuid": f"tf-analyze-{ts}",
            "metadata": {
                "title": "tf-analyze CIS Compliance Assessment",
                "last-modified": ts,
                "version": "1.0",
                "oscal-version": "1.1.2",
                "remarks": f"Generated by tf-analyze for target: {target_dir}",
            },
            "results": [
                {
                    "uuid": f"result-{ts}",
                    "title": f"tf-analyze scan",
                    "start": ts,
                    "findings": findings_oscal,
                }
            ],
        }
    }


# ---- Feature 1 (cont): Fix Priority HTML rendering ----------------------

def _render_fix_priority_html(scored: list[dict]) -> str:
    """Render the Fix Priority ranked table as an HTML panel."""
    if not scored:
        return (
            "<p style='color:#888;font-style:italic;padding:1em'>"
            "No attack-graph data available. Run with <code>--attack-graph</code> "
            "to enable centrality scoring.</p>"
        )
    rows = []
    for i, item in enumerate(scored, 1):
        score = item["impact"]
        score_cls = "critical" if score >= 15 else ("high" if score >= 8 else "medium")
        cp_badge = (
            "<span class='badge-cp'>CRITICAL-PATH</span>"
            if item["on_critical_path"] else ""
        )
        ir_badge = (
            "<span style='background:#d35400;color:#fff;padding:1px 6px;"
            "border-radius:3px;font-size:10px;font-weight:700;margin-left:4px'>"
            "INET-REACHABLE</span>"
            if item["internet_reachable"] else ""
        )
        # Audit fix #1 — fix-priority table: `finding_id` is validated
        # rule-id format, `resource` is user-controlled. Escape both.
        rows.append(
            f"<tr>"
            f"<td style='font-weight:700;text-align:center;width:2.5em'>{i}</td>"
            f"<td><code>{_h(item['finding_id'])}</code></td>"
            f"<td><code>{_h(item['resource'])}</code>{cp_badge}{ir_badge}</td>"
            f"<td style='text-align:center'>{item['crowns_blocked']}</td>"
            f"<td style='text-align:center'>"
            f"<span class='u u-{score_cls}'>{score}</span></td>"
            f"</tr>"
        )
    return (
        "<h2 style='margin-top:.5em'>Fix Priority</h2>"
        "<p style='color:#555;font-size:13px;margin-bottom:.8em'>"
        "Findings ranked by attack-path impact. "
        "<em>Crowns Blocked</em> = crown-jewel resources (RDS, S3, KMS, Secrets Manager) "
        "that become unreachable from the internet when this finding is fixed.</p>"
        "<table class='locs'><thead><tr>"
        "<th>#</th><th>Rule</th><th>Resource</th>"
        "<th>Crowns Blocked</th><th>Score</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def to_html(
    findings: list[dict],
    entries: list[dict],
    suppressed: list[dict],
    graph: dict | None = None,
    show_fixes: bool = False,
    centrality: list[dict] | None = None,
    compliance_data: dict | None = None,
    summary: dict | None = None,
) -> str:
    """Produce a single-file HTML report, scalable to hundreds of findings.

    Groups by catalogue ID, collapsible per group.  No external CSS/JS —
    self-contained for offline review.  When `graph` is provided (from
    build_attack_graph) an interactive Attack Graph tab is included.

    When ``summary`` is provided, a coloured banner is rendered above the
    findings panel showing score, grade, and per-urgency counts. The
    banner colour mirrors grade severity (A=green, B=lime, C=amber,
    D/F=red).
    """
    entry_map = {e["id"]: e for e in entries}
    by_id: dict[str, list[dict]] = {}
    for f in findings:
        by_id.setdefault(f["id"], []).append(f)
    # Audit fix #11 — share the single source of truth at module top.
    urgency_rank = URGENCY_RANK_ASCENDING
    sorted_ids = sorted(
        by_id.keys(),
        key=lambda i: (
            urgency_rank.get(entry_map.get(i, {}).get("default_urgency", "MEDIUM"), 2),
            -len(by_id[i]),
            i,
        ),
    )

    def _make_detail_rows(eid: str, urgency: str, fs: list[dict]) -> str:
        entry_local = entry_map.get(eid, {})
        parts = []
        for f in fs:
            # Audit fix #1 — every engine-supplied field rendered in
            # this row is escaped. `cp_badge` is a literal string.
            cp_badge = "<span class='badge-cp'>CRITICAL-PATH</span>" if f.get("on_critical_path") else ""
            parts.append(
                f"<tr><td><code>{_h(f.get('file',''))}</code>:{_h(str(f.get('line','')))}</td>"
                f"<td><code>{_h(f.get('resource',''))}</code>{cp_badge}</td></tr>"
            )
            if urgency in ("HIGH", "CRITICAL"):
                narrative = _narrative_for_finding(
                    eid, f.get("resource", ""), f.get("file", "")
                )
                if narrative:
                    # Audit fix #2 — narrative templates interpolate
                    # finding-supplied `resource` / `file` values;
                    # escape the rendered narrative before injecting
                    # into HTML so a resource name containing
                    # `<script>` cannot propagate.
                    parts.append(
                        f"<tr><td colspan='2'>"
                        f"<p class='narrative'>{_h(narrative)}</p>"
                        f"</td></tr>"
                    )
            if show_fixes and entry_local.get("fix_hcl"):
                hcl = entry_local["fix_hcl"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                disruption = entry_local.get("fix_disruption", "")
                d_badge = _disruption_badge(disruption)
                d_note = entry_local.get("fix_disruption_note", "")
                d_note_html = f"<p style='color:#888;font-size:11px;margin:.2em 0 .4em'>{_h(d_note)}</p>" if d_note else ""
                parts.append(
                    f"<tr><td colspan='2'>"
                    f"<details><summary style='cursor:pointer;color:#27ae60;font-size:12px;margin-top:.4em'>&#9654; Suggested fix{d_badge}</summary>"
                    f"{d_note_html}"
                    f"<pre class='fix-hcl'>{hcl}</pre></details>"
                    f"</td></tr>"
                )
        return "".join(parts)

    rows = []
    for eid in sorted_ids:
        entry = entry_map.get(eid, {})
        fs = by_id[eid]
        # Use effective urgency: per-finding reachability-adjusted urgency if available,
        # else catalogue default. Take the highest urgency among all findings for the summary badge.
        urgency = entry.get("default_urgency", "MEDIUM")
        eff_urgencies = [_effective_urgency(f, entry) for f in fs]
        # Audit fix #11 — `max` against descending rank picks the
        # *worst* urgency in the group. Previously this was an inline
        # dict that disagreed in sense with the ascending rank above
        # (CRITICAL=4 here vs CRITICAL=0 above) — exactly the drift
        # this audit-round consolidation prevents.
        display_urgency = max(
            eff_urgencies,
            key=lambda u: URGENCY_RANK_DESCENDING.get(u, 2),
        ) if eff_urgencies else urgency
        title = entry.get("title", eid)
        detail_rows = _make_detail_rows(eid, display_urgency, fs)
        docs_url = RULE_DOCS_URL_BASE.format(id=eid)
        # Audit fix #1 — `eid` is matched against `^[A-Z][A-Z0-9-]+$`
        # by the catalogue loader, so it's safe; `title` is engine-
        # supplied (and could come from a user-controlled catalogue
        # entry via `--catalog`), so it MUST be escaped. `docs_url` is
        # built from `eid` only (no user input) so safe.
        rows.append(
            f"<details><summary><span class='u u-{display_urgency.lower()}'>{_h(display_urgency)}</span> "
            f"<a href='{docs_url}' target='_blank' rel='noopener' "
            f"title='Open rule documentation'><b>{_h(eid)}</b></a> — {_h(title)} ({len(fs)})</summary>"
            f"<table class='locs'><thead><tr><th>Location</th><th>Resource</th></tr></thead>"
            f"<tbody>{detail_rows}</tbody></table></details>"
        )

    suppressed_section = ""
    if suppressed:
        sups = "".join(
            f"<li><code>{s['id']}</code> {s.get('file','')}:{s.get('line','')} — "
            f"{s.get('suppression_reason','')}</li>"
            for s in suppressed
        )
        suppressed_section = f"<h2>Suppressed ({len(suppressed)})</h2><ul>{sups}</ul>"

    findings_panel = f"{''.join(rows)}\n{suppressed_section}"

    # Risk-score banner (rendered above the tabs). Colour-banded by grade
    # so the headline number is visible at a glance without scrolling.
    summary_banner = ""
    if summary is not None:
        _grade_to_colour = {
            "A":  ("#1e7e34", "#d4edda"),
            "B":  ("#5d8e2d", "#e8f3d6"),
            "B-": ("#7a8a2d", "#f0f4d8"),
            "C":  ("#b07d00", "#fff3cd"),
            "D":  ("#a53f0d", "#fde4d4"),
            "F":  ("#a02020", "#f8d7da"),
        }
        fg, bg = _grade_to_colour.get(summary["grade"], ("#444", "#eee"))
        c = summary["counts"]
        sup = summary.get("suppressed_count", 0)
        sup_html = (
            f"<span style='color:#777;margin-left:.6em'>· {sup} suppressed</span>"
            if sup else ""
        )
        summary_banner = (
            f"<div style='background:{bg};border-left:6px solid {fg};"
            f"padding:.7em 1em;margin-bottom:1em;border-radius:0 4px 4px 0;"
            f"font-size:14px'>"
            f"<span style='font-size:24px;font-weight:700;color:{fg};margin-right:.4em'>"
            f"{summary['score']}</span>"
            f"<span style='font-size:18px;font-weight:600;color:{fg};margin-right:.8em'>"
            f"({summary['grade']})</span>"
            f"<span style='color:#1a1a1a'>"
            f"{c['CRITICAL']} <strong>CRITICAL</strong> · "
            f"{c['HIGH']} HIGH · {c['MEDIUM']} MEDIUM · "
            f"{c['LOW']} LOW · {c['INFO']} INFO"
            f"{sup_html}"
            f"</span>"
            f"<div style='font-size:11px;color:#666;margin-top:.3em'>"
            f"scoring_version {summary['scoring_version']} · "
            f"<code style='background:rgba(0,0,0,.05);padding:1px 4px;border-radius:2px'>"
            f"{summary['formula']}</code>"
            f"</div>"
            f"</div>"
        )

    tab_bar = ""
    tab_js = ""
    graph_panel_html = ""
    graph_tab_style = ""
    exec_panel_html = ""
    fixpri_panel_html = ""
    compliance_panel_html = ""
    if graph is not None:
        exec_content = _render_executive_view(findings, entries, graph)
        exec_panel_html = f"<div id='tp-exec' class='tab-panel' style='display:none;padding:1em'>{exec_content}</div>"
        fp_btn = (
            "<button class='tab-btn' onclick='showTab(\"fixpri\",this)'>"
            "&#127381; Fix Priority</button>"
            if centrality is not None else ""
        )
        comp_btn = (
            "<button class='tab-btn' onclick='showTab(\"compliance\",this)'>"
            "&#9989; Compliance</button>"
            if compliance_data is not None else ""
        )
        tab_bar = (
            "<div class='tab-bar'>"
            "<button class='tab-btn active' onclick='showTab(\"findings\",this)'>Findings</button>"
            "<button class='tab-btn' onclick='showTab(\"graph\",this)'>&#128200; Attack Graph</button>"
            "<button class='tab-btn' onclick='showTab(\"exec\",this)'>&#127919; Executive View</button>"
            f"{fp_btn}{comp_btn}"
            "</div>"
        )
        graph_tab_style = "display:none"
        graph_panel_html = _render_graph_html(graph)
        # R30.17 — Append a blast-radius table to the Attack Graph tab so
        # the SRE persona (the one who cares which resource a typo would
        # destroy) lands on the answer beside the visual graph that shows
        # *why*. Self-contained HTML; only fires when there are
        # non-leaf nodes (top_blast_radius_resources filters min_radius=1).
        try:
            from _blast_radius import (
                compute_blast_radius,
                top_blast_radius_resources,
                render_blast_radius_html,
            )
            _blast_map = compute_blast_radius(graph)
            _blast_top = top_blast_radius_resources(graph, _blast_map, top_n=10)
            graph_panel_html += render_blast_radius_html(_blast_top)
        except ImportError:
            pass  # blast-radius is opt-in alongside attack-graph
        tab_js = (
            "<script>"
            "function showTab(name,btn){"
            "document.querySelectorAll('.tab-panel').forEach(function(p){p.style.display='none';});"
            "document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});"
            "document.getElementById('tp-'+name).style.display='';"
            "btn.classList.add('active');}"
            "</script>"
        )
        fixpri_panel_html = (
            f"<div id='tp-fixpri' class='tab-panel' style='display:none;padding:1em'>"
            f"{_render_fix_priority_html(centrality)}"
            f"</div>"
            if centrality is not None else ""
        )
        compliance_panel_html = (
            f"<div id='tp-compliance' class='tab-panel' style='display:none;padding:1em'>"
            f"{_render_compliance_html(compliance_data)}"
            f"</div>"
            if compliance_data is not None else ""
        )

    if compliance_data is not None and graph is None:
        comp_btn = (
            "<button class='tab-btn' onclick='showTab(\"compliance\",this)'>"
            "&#9989; Compliance</button>"
        )
        tab_bar = (
            "<div class='tab-bar'>"
            "<button class='tab-btn active' onclick='showTab(\"findings\",this)'>Findings</button>"
            f"{comp_btn}"
            "</div>"
        )
        compliance_panel_html = (
            f"<div id='tp-compliance' class='tab-panel' style='display:none;padding:1em'>"
            f"{_render_compliance_html(compliance_data)}"
            f"</div>"
        )
        tab_js = (
            "<script>"
            "function showTab(name,btn){"
            "document.querySelectorAll('.tab-panel').forEach(function(p){p.style.display='none';});"
            "document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});"
            "document.getElementById('tp-'+name).style.display='';"
            "btn.classList.add('active');}"
            "</script>"
        )
        fixpri_panel_html = ""
        exec_panel_html = ""
        graph_tab_style = "display:none"
        graph_panel_html = ""

    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>tf-analyze report</title>
<style>
body{{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em;color:#222}}
code{{font:12px/1.3 ui-monospace,monospace;background:#f4f4f4;padding:1px 4px;border-radius:3px}}
details{{border:1px solid #e0e0e0;border-radius:6px;margin:.4em 0;padding:.6em 1em;background:#fafafa}}
summary{{cursor:pointer;user-select:none}}
.u{{padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600;color:#fff}}
.u-critical{{background:#7a0b0b}} .u-high{{background:#b02a2a}} .u-medium{{background:#c27a00}} .u-low{{background:#5a7b33}} .u-info{{background:#4a6a8a}}
.badge-cp{{background:#c0392b;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-left:4px;vertical-align:middle}}
table.locs{{border-collapse:collapse;margin-top:.5em;width:100%;font-size:13px}}
table.locs th,table.locs td{{text-align:left;padding:.3em .5em;border-bottom:1px solid #eee}}
h1{{margin:0 0 .2em}} .meta{{color:#666;margin-bottom:1em}}
p.narrative{{font-size:12px;color:#555;border-left:3px solid #b02a2a;padding:.3em .7em;margin:.4em 0;font-style:italic;background:#fff8f8;border-radius:0 4px 4px 0}}
.tab-bar{{border-bottom:2px solid #e0e0e0;margin-bottom:1em}}
.tab-btn{{background:none;border:none;padding:.45em 1.4em;cursor:pointer;font-size:13px;border-bottom:3px solid transparent;margin-bottom:-2px;color:#555;font-weight:500}}
.tab-btn.active{{border-bottom-color:#2980b9;color:#1a1a1a;font-weight:600}}
.tab-btn:hover{{color:#1a1a1a}}
pre.fix-hcl{{background:#1a1a2e;color:#a8d8a8;padding:.8em 1em;border-radius:4px;font-size:12px;overflow-x:auto;margin:.5em 0;border-left:3px solid #27ae60}}
</style></head><body>
<h1>tf-analyze report</h1>
<div class='meta'>{len(findings)} findings across {len(by_id)} rules.</div>
{summary_banner}
{tab_bar}
<div id='tp-findings' class='tab-panel'>
{findings_panel}
</div>
<div id='tp-graph' class='tab-panel' style='{graph_tab_style}'>
{graph_panel_html}
</div>
{exec_panel_html}
{fixpri_panel_html}
{compliance_panel_html}
{tab_js}
</body></html>
"""


