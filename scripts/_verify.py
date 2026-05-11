"""``--verify-fixed`` mode + ``--auto-stub`` / ``--gen-tftest`` helpers.

Six functions extracted from ``detect.py`` as the **seventeenth
modularisation seam**:

* :func:`parse_markdown_report` — extract ``(id, file, line)`` rows from
  a prior tf-analyze markdown report; tolerant of the report
  template's optional columns. Skips "Resolved since…" sections.
* :func:`reprobe_finding` — re-run a single catalogue entry against the
  current corpus to classify a prior finding as STILL-PRESENT,
  RESOLVED, MOVED, STALE-LOCATION, or AMBIGUOUS.
* :func:`verify_fixed` — top-level driver; parse + re-probe every prior
  finding, return the bucketed result dict.
* :func:`write_verification_report` — markdown rendering of the
  verification result.
* :func:`generate_stub` — scaffold a catalogue YAML stub for an
  exploratory finding (``--auto-stub`` flow).
* :func:`generate_tftest` — render ``.tftest.hcl`` assertion files
  from catalogue ``test_template`` fields, one per finding.

``reprobe_finding`` and ``verify_fixed`` need to call back into the
engine's scanners (``detect_in_file``, ``detect_corpus``) — those are
injected via keyword args so this module imports nothing from
``detect.py``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable


_FINDING_ROW_RE = re.compile(
    r'^\|\s*(?P<id>[A-Z]{2,4}(?:-[A-Z]+)+-\d{3})'
    r'(?:#\d+)?\s*\|'         # optional instance number
    r'(?P<middle>.*?)\|'       # skip urgency column(s)
    r'\s*`?(?P<file>[\w./-]+\.tf)`?'
    r'[:\s]*(?P<line>\d+)?'
    r'.*\|',
    re.MULTILINE,
)


def parse_markdown_report(path: Path) -> list[dict]:
    """Extract ``(id, file, line, resource)`` rows from a prior markdown report.

    The report template uses a findings table with at least these
    columns: ``| ID | urgency | file:line | resource | ... |``. Intentionally
    tolerant — any row containing a catalogue-shaped ID followed by a
    ``.tf`` path is captured. "Resolved since…" sections are skipped
    via section-heading tracking so a re-probe doesn't re-flag what
    the previous report already marked resolved.
    """
    text = path.read_text()
    rows: list[dict] = []
    current_section = ""
    in_resolved = False
    for line in text.splitlines():
        if line.startswith("#"):
            current_section = line.lower()
            in_resolved = "resolved" in current_section
            continue
        if in_resolved:
            continue
        m = _FINDING_ROW_RE.match(line)
        if not m:
            continue
        rows.append({
            "id": m.group("id"),
            "file": m.group("file"),
            "line": int(m.group("line")) if m.group("line") else 0,
            "resource": "",
        })
    return rows


def reprobe_finding(
    finding: dict,
    catalog_by_id: dict,
    all_files_text: dict,
    *,
    detect_in_file: Callable[[Path, str, list], list[dict]],
    detect_corpus: Callable[[Path, dict, list], list[dict]],
) -> str:
    """One of: STILL-PRESENT, RESOLVED, MOVED, STALE-LOCATION, AMBIGUOUS.

    Strategy: re-run just this catalogue entry against the named file
    (or all files, for corpus-level finders). If the pattern fires
    within ±3 lines of the original, STILL-PRESENT. Fires in a
    different file → MOVED. Doesn't fire anywhere → RESOLVED. File
    gone → STALE-LOCATION. Entry missing from catalogue → AMBIGUOUS.
    """
    entry = catalog_by_id.get(finding["id"])
    if not entry:
        return "AMBIGUOUS"
    target_file = Path(finding["file"])

    hits: list[dict] = []
    for fp, text in all_files_text.items():
        hits.extend(detect_in_file(fp, text, [entry]))
    hits.extend(detect_corpus(Path("."), all_files_text, [entry]))

    same_file = [h for h in hits if str(h.get("file", "")) == str(target_file)]
    if same_file:
        if any(abs(h["line"] - finding["line"]) <= 3 for h in same_file):
            return "STILL-PRESENT"
        return "MOVED"
    if hits:
        return "MOVED"
    # Round-5 audit fix #16 — distinguish a broken symlink from a
    # missing file. `Path.exists()` returns False for both, so an
    # operator looking at a STALE-LOCATION finding couldn't tell
    # whether the file was deleted or whether its symlink target
    # was broken (which has a different remediation — fix the
    # symlink, don't update the report). `is_symlink()` is True
    # iff the path *itself* is a symlink, regardless of target.
    if not target_file.exists():
        if target_file.is_symlink():
            return "BROKEN-SYMLINK"
        return "STALE-LOCATION"
    return "RESOLVED"


def verify_fixed(
    prior_report: Path,
    target: Path,
    all_files_text: dict,
    entries: list[dict],
    *,
    detect_in_file: Callable[[Path, str, list], list[dict]],
    detect_corpus: Callable[[Path, dict, list], list[dict]],
) -> dict:
    """Parse prior report, re-probe every finding, return a verification dict."""
    prior_findings = parse_markdown_report(prior_report)
    catalog_by_id = {e["id"]: e for e in entries}
    results: dict[str, list[dict]] = {
        "STILL-PRESENT": [],
        "RESOLVED": [],
        "MOVED": [],
        "STALE-LOCATION": [],
        "AMBIGUOUS": [],
    }
    for f in prior_findings:
        state = reprobe_finding(
            f, catalog_by_id, all_files_text,
            detect_in_file=detect_in_file,
            detect_corpus=detect_corpus,
        )
        results[state].append(f)
    return {
        "prior_report": str(prior_report),
        "total_prior": len(prior_findings),
        "results": results,
    }


def write_verification_report(verify: dict, out_path: Path) -> None:
    """Render the verification dict as markdown."""
    lines = [
        "# Terraform Code Analysis — Verification Report",
        "",
        f"**Prior report:** `{verify['prior_report']}`",
        f"**Total prior findings:** {verify['total_prior']}",
        "",
        "## Summary",
        "",
        "| State | Count |",
        "|---|---|",
    ]
    for state, rows in verify["results"].items():
        lines.append(f"| {state} | {len(rows)} |")
    lines.append("")
    for state, rows in verify["results"].items():
        if not rows:
            continue
        lines.append(f"## {state}")
        lines.append("")
        lines.append("| ID | File | Line |")
        lines.append("|---|---|---|")
        for r in rows:
            lines.append(f"| {r['id']} | `{r['file']}` | {r.get('line','')} |")
        lines.append("")
    out_path.write_text("\n".join(lines))


def generate_stub(finding_id: str, finding: dict, stub_dir: Path) -> Path | None:
    """Scaffold a catalogue YAML stub for an exploratory finding.

    Returns the written path, or ``None`` if a stub for this ID
    already exists (refuses to overwrite — a real authoring session
    starts from the existing draft, not a regen from scratch).
    """
    safe_id = re.sub(r'[^A-Za-z0-9_-]', '_', finding_id)
    stub_path = stub_dir / f"{safe_id}.yaml"
    if stub_path.exists():
        return None

    content = f"""id: {safe_id}
title: "TODO: describe finding"
section: robustness
default_urgency: MEDIUM
blast_radius: single-resource
status: stub
patterns:
  - kind: grep
    file_glob: "**/*.tf"
    regex: 'TODO: add detection pattern'
    description: TODO
recommendation: |
  TODO: describe recommended fix.
verification: |
  TODO: describe how to verify the fix.
"""
    stub_path.write_text(content)
    return stub_path


def generate_tftest(
    findings: list[dict],
    entries: list[dict],
    out_dir: Path,
) -> list[Path]:
    """Render ``.tftest.hcl`` files from catalogue ``test_template`` fields.

    One file per (finding_id, resource) pair to keep the generated
    suite mappable back to its triggering findings. Skips entries
    without a ``test_template``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    entry_map = {e["id"]: e for e in entries}
    written: list[Path] = []
    seen: set[str] = set()
    for f in findings:
        entry = entry_map.get(f["id"])
        if not entry:
            continue
        tmpl = entry.get("test_template")
        if not tmpl:
            continue
        resource = f.get("resource", "unknown")
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", resource)
        key = f"{f['id']}_{safe}"
        if key in seen:
            continue
        seen.add(key)
        rendered = tmpl.replace("{resource}", resource).replace("{rule_id}", f["id"])
        out_path = out_dir / f"{key}.tftest.hcl"
        out_path.write_text(rendered)
        written.append(out_path)
    return written
