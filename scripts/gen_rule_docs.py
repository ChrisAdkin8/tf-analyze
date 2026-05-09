#!/usr/bin/env python3
"""Generate one Markdown page per catalogue rule under ``docs/rules/``.

Each page renders the catalogue YAML's content into a reader-friendly
shape: title + urgency badge, what the rule checks, why it likely
fired, the adversarial scenario (when present), the remediation
snippet with disruption classification, verification commands, and
references (CIS / PCI-DSS / SOC2 / MITRE ATT&CK / related rules).

The page is the canonical link target for:
  - the HTML compliance panel ("FAIL: SEC-AWS-IAM-001 fired" → click)
  - SARIF ``helpUri`` (GitHub Code Scanning, Azure DevOps)
  - VS Code extension hover panel
  - Slack / JIRA / runbook pasteable URLs

The catalogue YAML is the source of truth. Run after any catalogue
edit, or have CI regenerate on every release tag.

Usage:
  python3 scripts/gen_rule_docs.py            # write docs/rules/*.md
  python3 scripts/gen_rule_docs.py --check    # verify docs are up to date (CI gate)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalog"
DOCS_RULES_DIR = REPO_ROOT / "docs" / "rules"
SOURCE_URL_BASE = "https://github.com/ChrisAdkin8/tf-analyze/blob/main/catalog/{id}.yaml"
MITRE_URL_BASE = "https://attack.mitre.org/techniques/{tid_with_slash}/"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from detect import load_yaml  # type: ignore  # noqa: E402

URGENCY_BADGE = {
    "CRITICAL": ("![CRITICAL](https://img.shields.io/badge/CRITICAL-c0392b?style=flat-square)", "🚨"),
    "HIGH":     ("![HIGH](https://img.shields.io/badge/HIGH-e67e22?style=flat-square)", "⚠️"),
    "MEDIUM":   ("![MEDIUM](https://img.shields.io/badge/MEDIUM-f1c40f?style=flat-square)", "💡"),
    "LOW":      ("![LOW](https://img.shields.io/badge/LOW-95a5a6?style=flat-square)", "ℹ️"),
    "INFO":     ("![INFO](https://img.shields.io/badge/INFO-3498db?style=flat-square)", "·"),
}

DISRUPTION_BADGE = {
    "none":              "![Non-disruptive](https://img.shields.io/badge/non--disruptive-27ae60?style=flat-square)",
    "plan_required":     "![Plan required](https://img.shields.io/badge/plan%20required-e67e22?style=flat-square)",
    "forces_replacement": "![Forces replacement](https://img.shields.io/badge/forces%20replacement-c0392b?style=flat-square)",
}

KIND_EXPLAINER = {
    "resource_arg": "the resource declares the named attribute, but its value matches the rule's pattern",
    "resource_missing_arg": "the resource is missing a required attribute (or nested attribute path)",
    "resource_present": "this resource type exists in the corpus and is itself a finding",
    "resource_absent": "the corpus is missing a resource type we expected to find given other resources present",
    "resource_body_contains": "the resource body matches a regex inside the block",
    "hcl_attr": "an attribute value differs from the expected literal",
    "iam_policy_analysis": "a `data \"aws_iam_policy_document\"` Allow statement matches the listed check",
    "iam_json_policy_analysis": "an inline `policy = jsonencode({...})` Allow statement matches the listed check",
    "helm_set_value": "a `helm_release` `set { name = ...; value = ... }` override matches the listed condition",
    "graph_check": "a corpus-wide graph check fired (cross-resource invariant)",
    "grep": "a textual regex matched somewhere in the file",
    "firewall_open_port": "a `google_compute_firewall` allows the named port from `0.0.0.0/0`",
    "intent_gap": "the variable-name suggests one intent but the resource configuration contradicts it",
    "removed_block_present": "a `removed { ... }` block exists with a stale target",
    "moved_block_present": "a `moved { ... }` block points at a target that no longer exists",
    "templatefile_sensitive_leak": "a `templatefile()` call passes a sensitive variable to a template",
    "tfstate_in_repo": "a `*.tfstate` file is committed to the repository",
}


def _section(title: str, body: str) -> str:
    body = body.strip()
    if not body:
        return ""
    return f"## {title}\n\n{body}\n\n"


def _hcl_block(content: str) -> str:
    return f"```hcl\n{content.strip()}\n```"


def _shell_block(content: str) -> str:
    return f"```sh\n{content.strip()}\n```"


def _patterns_explainer(patterns: list[dict]) -> str:
    lines: list[str] = []
    for i, p in enumerate(patterns, 1):
        kind = p.get("kind", "?")
        explainer = KIND_EXPLAINER.get(kind, f"a `{kind}` pattern")
        rt = p.get("resource", "")
        rt_part = f" on `{rt}`" if rt else ""
        arg = p.get("arg") or p.get("nested_path") or p.get("path") or ""
        arg_part = f" (`{arg}`)" if arg else ""
        regex = p.get("regex")
        regex_part = f" matching `/{regex}/`" if regex else ""
        not_eq = p.get("not_equal")
        not_eq_part = f" not equal to `{not_eq}`" if not_eq is not None else ""
        check = p.get("check")
        check_part = f" — check: `{check}`" if check else ""
        desc = (p.get("description") or "").strip()
        desc_part = f"\n  {desc}" if desc else ""
        lines.append(
            f"{i}. **`{kind}`**{rt_part}{arg_part}{regex_part}{not_eq_part}{check_part} — "
            f"_{explainer}._{desc_part}"
        )
    return "\n".join(lines)


def _references(entry: dict, rule_id: str) -> str:
    parts: list[str] = []
    cis = entry.get("cis") or []
    if cis:
        cis_items: list[str] = []
        for c in cis:
            if isinstance(c, dict):
                ref = f"CIS {c.get('id', '?')}"
                title = c.get("title", "")
                cis_items.append(f"  - `{ref}`{(' — ' + title) if title else ''}")
            else:
                cis_items.append(f"  - `CIS {c}`")
        parts.append("**CIS Benchmark**\n" + "\n".join(cis_items))
    pci = entry.get("pci_dss") or []
    if pci:
        parts.append("**PCI-DSS**\n" + "\n".join(f"  - `{p}`" for p in pci))
    soc2 = entry.get("soc2_cc") or []
    if soc2:
        parts.append("**SOC 2 Trust Services Criteria**\n" + "\n".join(f"  - `{s}`" for s in soc2))
    mitre = entry.get("mitre") or []
    if mitre:
        mitre_links = []
        for tid in mitre:
            tid_with_slash = str(tid).replace(".", "/")
            url = MITRE_URL_BASE.format(tid_with_slash=tid_with_slash)
            mitre_links.append(f"  - [`{tid}`]({url})")
        parts.append("**MITRE ATT&CK**\n" + "\n".join(mitre_links))
    related = entry.get("related") or []
    if related:
        rel_links = [f"  - [`{r}`](./{r}.md)" for r in related]
        parts.append("**Related rules**\n" + "\n".join(rel_links))
    parts.append(
        f"**Source**\n  - [`catalog/{rule_id}.yaml`]"
        f"({SOURCE_URL_BASE.format(id=rule_id)}) — canonical YAML"
    )
    return "\n\n".join(parts)


def render_rule_md(entry: dict) -> str:
    rule_id = entry["id"]
    title = entry.get("title", rule_id)
    urgency = entry.get("default_urgency", "MEDIUM")
    badge_md, emoji = URGENCY_BADGE.get(urgency, URGENCY_BADGE["MEDIUM"])
    section = entry.get("section", "?")
    blast = entry.get("blast_radius", "?")
    status = entry.get("status", "active")

    # Header — H1 + badges + a one-liner summary
    header = (
        f"# {emoji} {rule_id} — {title}\n\n"
        f"{badge_md} "
        f"![Section: {section}](https://img.shields.io/badge/section-{section}-blue?style=flat-square) "
        f"![Blast radius: {blast}](https://img.shields.io/badge/blast%20radius-{blast.replace('-', '--')}-purple?style=flat-square)"
    )
    if status != "active":
        header += f" ![Status: {status}](https://img.shields.io/badge/status-{status}-grey?style=flat-square)"
    header += "\n\n"

    # Summary derived from the title (the YAML's `title` is the
    # one-liner shape the catalog already uses).
    summary = (
        f"> **{title}.** "
        f"This rule has `default_urgency: {urgency}` and operates on a "
        f"{blast.replace('-', ' ')} blast radius. "
    )
    applies = entry.get("applies_when") or {}
    if applies:
        notes = []
        if "min_provider" in applies:
            for prov, ver in applies["min_provider"].items():
                notes.append(f"`{prov} ≥ {ver}`")
        if "min_terraform" in applies:
            notes.append(f"`terraform ≥ {applies['min_terraform']}`")
        if notes:
            summary += f"_Conditional: only applies when {', '.join(notes)}._"
    summary += "\n\n"

    # What this checks
    what_checks = _patterns_explainer(entry.get("patterns") or [])
    what_section = _section("What this checks", what_checks)

    # Why it likely fired — derived from pattern descriptions
    descs = [
        (p.get("description") or "").strip()
        for p in (entry.get("patterns") or [])
        if (p.get("description") or "").strip()
    ]
    why_body = (
        "\n\n".join(descs) if descs else
        "Walk the patterns above against the flagged resource. The detector "
        "ran when the listed conditions were satisfied; review the source "
        "line in your scan output to see the exact match."
    )
    why_section = _section("Why it likely fired", why_body)

    # Adversarial scenario (when the rule has a narrative — narratives
    # live in detect.py's _ATTACK_NARRATIVES; we don't have them in the
    # catalogue YAML, so we link the runtime feature here).
    narrative_section = _section(
        "Adversarial scenario",
        "HIGH and CRITICAL findings carry a 3–4 sentence adversarial "
        "narrative grounded in real incidents (Capital One, Accenture, "
        "SolarWinds). Run `python3 scripts/detect.py --explain "
        f"{rule_id}` or hover the squiggle in the VS Code extension to "
        "see the rendered narrative for this rule.\n\n"
        "Narratives are baked into the engine "
        "([`scripts/detect.py`](https://github.com/ChrisAdkin8/tf-analyze/blob/main/scripts/detect.py))"
        " under `_ATTACK_NARRATIVES` and emitted into the JSON output as the "
        "`narrative` field on every finding for this rule."
    )

    # Recommendation
    rec = (entry.get("recommendation") or "").strip()
    rec_section = _section("Remediation", rec) if rec else ""

    # fix_hcl + disruption
    fix = (entry.get("fix_hcl") or "").strip()
    if fix:
        disruption = entry.get("fix_disruption", "")
        d_badge = DISRUPTION_BADGE.get(disruption, "")
        d_note = (entry.get("fix_disruption_note") or "").strip()
        fix_body = ""
        if d_badge:
            fix_body += d_badge + "\n\n"
        fix_body += _hcl_block(fix)
        if d_note:
            fix_body += f"\n\n_{d_note}_"
        fix_section = _section("Suggested fix (`fix_hcl`)", fix_body)
    else:
        fix_section = ""

    # Verification
    verify = (entry.get("verification") or "").strip()
    verify_section = ""
    if verify:
        # Heuristic: if the body looks like shell, fence as sh; else as plain
        first = verify.splitlines()[0].strip() if verify else ""
        if first and (first.startswith(("`", "aws", "gcloud", "kubectl", "az "))):
            verify_section = _section("Verification", _shell_block(verify))
        else:
            verify_section = _section("Verification", verify)

    # References
    refs = _references(entry, rule_id)
    refs_section = _section("References", refs)

    # Footer — link back to index + how to run / suppress
    footer = (
        "---\n\n"
        "## Run this check\n\n"
        "```sh\n"
        f"python3 scripts/detect.py --explain {rule_id}    # full catalogue entry\n"
        f"python3 scripts/detect.py --target . --only-fixture <fixture>\n"
        "```\n\n"
        "## Suppress\n\n"
        f"Inline (single occurrence): `# tf-analyze:ignore {rule_id}` on or "
        "above the offending line.\n\n"
        "Project-wide: add to `.tf-analyze.yaml`:\n\n"
        "```yaml\n"
        "ignore_rules:\n"
        f"  - {rule_id}\n"
        "```\n\n"
        "Baseline (preserves but doesn't fail CI): scan with `--baseline "
        "prior.json` after a one-time snapshot.\n\n"
        # `../` because Pages serves rule pages at /rules/<id>/ — `./`
        # from there resolves back to the same page. `../` lands on
        # /rules/, which Jekyll serves as the index.
        f"[← Index of all rules](../)\n"
    )

    return (
        header + summary
        + what_section + why_section + narrative_section
        + rec_section + fix_section + verify_section
        + refs_section + footer
    )


def render_index(entries: list[dict]) -> str:
    """Sortable table of every rule, grouped by section."""
    by_section: dict[str, list[dict]] = {}
    for e in entries:
        if e.get("status") in ("deprecated",):
            continue
        by_section.setdefault(e.get("section", "other"), []).append(e)

    URG_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    out = [
        "---",
        "title: tf-analyze rule reference",
        "---",
        "",
        "# tf-analyze rule reference",
        "",
        "Per-rule documentation auto-generated from the catalogue YAML "
        "([`catalog/`](https://github.com/ChrisAdkin8/tf-analyze/tree/main/catalog)).",
        "",
        f"**{len(entries)} rules** across {len(by_section)} sections. "
        "Click any rule ID for the full description, remediation, and verification.",
        "",
        "---",
        "",
    ]
    for section in sorted(by_section):
        rules = sorted(
            by_section[section],
            key=lambda e: (URG_RANK.get(e.get("default_urgency", "MEDIUM"), 9), e["id"]),
        )
        out.append(f"## {section} ({len(rules)})")
        out.append("")
        out.append("| Rule | Urgency | Title |")
        out.append("|------|---------|-------|")
        for e in rules:
            urg = e.get("default_urgency", "?")
            out.append(
                f"| [`{e['id']}`](./{e['id']}.md) | {urg} | {e.get('title', '').replace('|', '\\|')} |"
            )
        out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="Verify docs/rules/ matches the catalogue. Exit 1 if stale (for CI gating).")
    args = ap.parse_args()

    DOCS_RULES_DIR.mkdir(parents=True, exist_ok=True)

    entries: list[dict] = []
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            entry = load_yaml(yml.read_text())
        except Exception as e:
            print(f"  WARN: cannot parse {yml.name}: {e}", file=sys.stderr)
            continue
        if entry.get("status") == "deprecated":
            continue
        entries.append(entry)

    drift_count = 0
    for entry in entries:
        rule_id = entry["id"]
        target = DOCS_RULES_DIR / f"{rule_id}.md"
        rendered = render_rule_md(entry)
        if args.check:
            current = target.read_text() if target.exists() else ""
            if current != rendered:
                drift_count += 1
                print(f"  STALE: {target.relative_to(REPO_ROOT)}", file=sys.stderr)
        else:
            target.write_text(rendered)

    index_target = DOCS_RULES_DIR / "index.md"
    rendered_index = render_index(entries)
    if args.check:
        current_index = index_target.read_text() if index_target.exists() else ""
        if current_index != rendered_index:
            drift_count += 1
            print(f"  STALE: {index_target.relative_to(REPO_ROOT)}", file=sys.stderr)
    else:
        index_target.write_text(rendered_index)

    if args.check:
        if drift_count:
            print(f"\nERROR: {drift_count} doc(s) out of sync with catalogue. "
                  f"Run `python3 scripts/gen_rule_docs.py`.", file=sys.stderr)
            return 1
        print(f"OK: {len(entries)} rule docs in sync.", file=sys.stderr)
        return 0

    print(f"Wrote {len(entries)} rule docs + index to "
          f"{DOCS_RULES_DIR.relative_to(REPO_ROOT)}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
