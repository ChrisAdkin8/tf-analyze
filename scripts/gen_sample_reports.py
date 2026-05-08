#!/usr/bin/env python3
"""Regenerate the sample reports under `reports/` from the terragoat corpus.

For each scope (aws, gcp, azure, all), this script:

  1. Runs ``detect.py --target examples/terragoat/<scope> --format json
     --attack-graph`` and writes the raw JSON.
  2. Renders a curated executive-style markdown report from that JSON
     (score banner, executive summary, top findings, MITRE coverage,
     attack-graph mermaid, suggested fixes).

Run:

  python3 scripts/gen_sample_reports.py [--date YYYY-MM-DD]

Default date is today (UTC). Old reports are kept; the script writes
new files with the chosen date suffix.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"
TERRAGOAT = REPO_ROOT / "examples" / "terragoat"
REPORTS_DIR = REPO_ROOT / "reports"

URGENCY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
URGENCY_BADGE = {
    "CRITICAL": "🚨",
    "HIGH": "⚠️",
    "MEDIUM": "💡",
    "LOW": "ℹ️",
    "INFO": "·",
}


def run_detect(target: Path) -> dict:
    """Run detect.py and return parsed JSON."""
    cmd = [
        sys.executable, str(DETECT_PY),
        "--target", str(target),
        "--format", "json",
        "--attack-graph",
        "--no-hcl2",   # keep the regex parser for reproducibility
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if res.returncode > 1:
        # exit 1 means findings exist (expected); >1 means an actual error
        sys.exit(f"detect.py exited {res.returncode}: {res.stderr}")
    return json.loads(res.stdout)


def _relpath(p: str) -> str:
    """Strip the absolute repo prefix from a finding path for cleaner output."""
    abs_root = str(REPO_ROOT) + "/"
    return p.removeprefix(abs_root)


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            URGENCY_RANK.get(f.get("urgency", "MEDIUM"), 9),
            f.get("id", ""),
            f.get("file", ""),
            f.get("line", 0),
        ),
    )


def _findings_table(findings: list[dict], limit: int = 10) -> str:
    if not findings:
        return "_(none)_\n"
    rows = ["| Rule | Urgency | File:Line | Resource |",
            "|------|---------|-----------|----------|"]
    for f in findings[:limit]:
        rows.append(
            f"| `{f['id']}` | {f.get('urgency','?')} | "
            f"`{_relpath(f.get('file',''))}`:{f.get('line','?')} | "
            f"`{f.get('resource','') or '—'}` |"
        )
    if len(findings) > limit:
        rows.append(f"| _… {len(findings) - limit} more_ |  |  |  |")
    return "\n".join(rows) + "\n"


def _mitre_breakdown(findings: list[dict]) -> str:
    by_tech: dict[str, list[dict]] = {}
    for f in findings:
        for t in f.get("mitre", []) or []:
            by_tech.setdefault(t, []).append(f)
    if not by_tech:
        return "_No MITRE-tagged findings in this corpus._\n"
    rows = ["| Technique | Findings | Example rule |",
            "|-----------|---------:|--------------|"]
    for tech in sorted(by_tech, key=lambda t: (-len(by_tech[t]), t)):
        group = by_tech[tech]
        # Highest-urgency rule in the group as the example.
        example = sorted(
            group,
            key=lambda f: URGENCY_RANK.get(f.get("urgency", "MEDIUM"), 9)
        )[0]
        rows.append(f"| `{tech}` | {len(group)} | `{example['id']}` ({example.get('urgency','?')}) |")
    return "\n".join(rows) + "\n"


def _top_fix_priority(findings: list[dict], limit: int = 5) -> str:
    """Pick HIGH/CRITICAL findings whose fix is most leveraged.

    detect.py only emits centrality scores via the HTML Fix Priority tab;
    here we approximate by ranking on (urgency, has fix_hcl, narrative
    length). The intent is to surface fixes a reader would want first.
    """
    candidates = [f for f in findings if f.get("urgency") in ("CRITICAL", "HIGH")
                  and f.get("fix_hcl")]
    candidates.sort(key=lambda f: (
        URGENCY_RANK.get(f.get("urgency", "MEDIUM"), 9),
        -len(f.get("narrative", "") or ""),
        f.get("id", ""),
    ))
    out: list[str] = []
    seen_ids: set[str] = set()
    for f in candidates:
        if f["id"] in seen_ids:
            continue
        seen_ids.add(f["id"])
        if len(out) >= limit:
            break
        fix = f["fix_hcl"].rstrip()
        disruption = f.get("fix_disruption", "unknown")
        out.append(
            f"### {URGENCY_BADGE.get(f.get('urgency','?'),'·')} "
            f"`{f['id']}` — {f.get('title','?')}\n"
            f"\n"
            f"**Disruption:** `{disruption}`  ·  "
            f"**Resource:** `{f.get('resource','—')}`  ·  "
            f"**Location:** `{_relpath(f.get('file',''))}`:{f.get('line','?')}\n"
            f"\n"
            f"```hcl\n{fix}\n```\n"
        )
    if not out:
        return "_(no HIGH/CRITICAL findings with `fix_hcl` in this corpus)_\n"
    return "\n".join(out)


def _attack_graph_summary(graph: dict | None) -> str:
    if not graph or not graph.get("nodes"):
        return "_(no attack graph for this corpus)_\n"
    nodes = graph["nodes"]
    edges = graph.get("edges", [])
    crowns = [n for n in nodes if n.get("is_crown_jewel")]
    inet = [n for n in nodes if n.get("internet_reachable")]
    crit_path = graph.get("critical_path") or []
    return (
        f"- **Nodes:** {len(nodes)} resources, **{len(edges)} edges**\n"
        f"- **Crown jewels:** {len(crowns)} "
        f"(databases, KMS keys, secrets, buckets)\n"
        f"- **Internet-reachable:** {len(inet)} entry-point resources\n"
        f"- **Critical path length:** {len(crit_path)} hops "
        f"({' → '.join(f'`{n}`' for n in crit_path) if crit_path else '_none_'})\n"
    )


def render_markdown(scope: str, data: dict, scope_path: Path, date: str) -> str:
    summary = data.get("summary", {})
    findings = _sorted_findings(data.get("findings", []))
    crit = [f for f in findings if f.get("urgency") == "CRITICAL"]
    high = [f for f in findings if f.get("urgency") == "HIGH"]
    medium = [f for f in findings if f.get("urgency") == "MEDIUM"]
    low = [f for f in findings if f.get("urgency") == "LOW"]
    info = [f for f in findings if f.get("urgency") == "INFO"]

    cmd = (
        f"python3 scripts/detect.py "
        f"--target {scope_path.relative_to(REPO_ROOT)} "
        f"--format json --attack-graph"
    )

    score = summary.get("score", "?")
    grade = summary.get("grade", "?")
    formula = summary.get("formula", "?")

    sections = [
        f"# tf-analyze sample report — terragoat `{scope}` ({date})",
        "",
        f"> Generated from [`{scope_path.relative_to(REPO_ROOT)}`]"
        f"(../{scope_path.relative_to(REPO_ROOT)}) — an intentionally-vulnerable "
        f"Terraform corpus modelled on Bridgecrew's [terragoat]"
        f"(https://github.com/bridgecrewio/terragoat). The score is **expected** "
        f"to be poor; this report exists to demonstrate the tool's output, not "
        f"to grade real infrastructure.",
        "",
        "---",
        "",
        "## 📊 Risk score",
        "",
        f"**{score} / 100  ·  Grade {grade}**",
        "",
        f"| 🚨 CRITICAL | ⚠️ HIGH | 💡 MEDIUM | ℹ️ LOW | INFO | Suppressed |",
        f"|---:|---:|---:|---:|---:|---:|",
        f"| **{len(crit)}** | **{len(high)}** | {len(medium)} | "
        f"{len(low)} | {len(info)} | "
        f"{summary.get('suppressed_count', 0)} |",
        "",
        f"<sub>Scoring version `{summary.get('scoring_version', '?')}`. "
        f"Formula: `{formula}`</sub>",
        "",
        "---",
        "",
        "## 🎯 Executive summary",
        "",
        f"`detect.py` flagged **{len(findings)} finding(s)** across "
        f"**{len({f['id'] for f in findings})} unique catalogue rules** "
        f"in {scope}. The corpus deliberately exercises every OWASP Top-10 "
        f"category, so a clean run is not the goal — these findings are the "
        f"intended demonstrations.",
        "",
        f"- {len(crit)} CRITICAL — immediate-blast: data exposure, privesc, "
        "audit blackout",
        f"- {len(high)} HIGH — direct security boundary breach with realistic "
        "exploit path",
        f"- {len(medium)} MEDIUM — defence-in-depth gaps",
        f"- {len(low)} LOW — hygiene and style",
        "",
        "---",
        "",
        "## 🚨 CRITICAL findings",
        "",
        _findings_table(crit, limit=15),
        "",
        "## ⚠️ HIGH findings",
        "",
        _findings_table(high, limit=15),
        "",
        "## 🔗 MITRE ATT&CK coverage",
        "",
        "Findings carry MITRE ATT&CK technique IDs where the catalogue rule has "
        "a confident mapping. Counts are per-finding (a rule mapped to two "
        "techniques contributes to both rows).",
        "",
        _mitre_breakdown(findings),
        "",
        "---",
        "",
        "## 🛤️  Attack graph",
        "",
        "Built by `--attack-graph`. Each resource is a node; edges are "
        "IAM/network/dependency references. The critical path is BFS from "
        "`INTERNET` to the most-exposed crown jewel.",
        "",
        _attack_graph_summary(data.get("graph")),
        "",
        "---",
        "",
        "## 🛠️  Top suggested fixes",
        "",
        "Highest-urgency findings with `fix_hcl` snippets. Disruption labels "
        "indicate operational impact: `none` = config-only re-plan, "
        "`plan_required` = a Terraform plan must be reviewed, "
        "`forces_replacement` = resource is destroyed and recreated.",
        "",
        _top_fix_priority(findings, limit=5),
        "---",
        "",
        "## 🔁 Reproduce",
        "",
        f"```sh",
        f"{cmd}",
        f"```",
        "",
        f"This report file was generated by "
        f"`scripts/gen_sample_reports.py` on **{date}**.",
        "",
    ]
    return "\n".join(sections)


def regenerate(scope: str, scope_path: Path, date: str) -> tuple[Path, Path]:
    """Run detect.py and write JSON + Markdown sample reports."""
    data = run_detect(scope_path)

    json_path = REPORTS_DIR / f"tf-analysis-{scope}-{date}.json"
    md_path = REPORTS_DIR / f"tf-analysis-{scope}-{date}.md"

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(data, indent=2) + "\n")
    md_path.write_text(render_markdown(scope, data, scope_path, date))

    summary = data.get("summary", {})
    print(
        f"  {scope:<6} → {summary.get('score','?')} ({summary.get('grade','?')}) "
        f"·  {len(data.get('findings', []))} findings → "
        f"{md_path.relative_to(REPO_ROOT)}, "
        f"{json_path.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    return md_path, json_path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--date",
        default=_dt.date.today().isoformat(),
        help="Date suffix for the report filenames (default: today)",
    )
    args = ap.parse_args()

    scopes = [
        ("aws",   TERRAGOAT / "aws"),
        ("gcp",   TERRAGOAT / "gcp"),
        ("azure", TERRAGOAT / "azure"),
        ("all",   TERRAGOAT),
    ]

    print(f"# Regenerating sample reports for date={args.date}", file=sys.stderr)
    for name, path in scopes:
        if not path.exists():
            print(f"  SKIP {name}: {path} not found", file=sys.stderr)
            continue
        regenerate(name, path, args.date)

    return 0


if __name__ == "__main__":
    sys.exit(main())
