"""Fleet + trend modes (``--mode fleet`` and ``--mode trend``).

Two subcommand families that share nothing with the main per-file
scan flow except scan callables and the catalogue entries:

* **Fleet mode** — scan N target repos, cross-correlate findings that
  appear in more than one. Surfaces "the same misconfig is in every
  team's repo" without forcing manual ad-hoc audits.
* **Trend mode** — walk a single repo's git history backward over
  the last N days, re-scan each commit, emit a per-commit
  new/resolved/net/total table. Answers "is the team's IaC posture
  improving or rotting?".

Both functions use the **callable-injection** pattern from ``_lsp.py``
(R30.7) so this module doesn't import detect.py — the heavyweight
helpers (``detect_corpus``, ``detect_in_file``, ``read_normalized``)
are passed in by the caller. That keeps the seam testable in
isolation and prevents the circular-import hazard.

Extracted from ``detect.py`` as the **sixteenth modularisation seam**.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Callable


def resolve_fleet_targets(args) -> list[Path]:
    """Collect target directories from ``--target`` and ``--targets-file``."""
    targets: list[Path] = [Path(t).resolve() for t in (args.targets or [])]
    tf_path_attr = getattr(args, "targets_file", None)
    if tf_path_attr:
        tf_path = Path(tf_path_attr)
        if tf_path.exists():
            for line in tf_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(Path(line).resolve())
    return targets


def fleet_scan(
    targets: list[Path],
    entries: list[dict],
    *,
    read_normalized: Callable[[Path], str],
    detect_corpus: Callable[[Path, dict, list], list[dict]],
    detect_in_file: Callable[[Path, str, list], list[dict]],
) -> dict:
    """Scan multiple repos and cross-correlate findings.

    Returns::

        {
          "by_target": {str(target): [findings]},
          "fleet_wide": [findings with fleet_count > 1],
          "summary": {str(target): int},
        }
    """
    by_target: dict[str, list[dict]] = {}
    for target in targets:
        tf_files = [p for p in target.rglob("*.tf") if ".terraform" not in p.parts]
        all_text: dict = {}
        for fp in tf_files:
            try:
                all_text[fp] = read_normalized(fp)
            except Exception:
                continue
        target_findings = detect_corpus(target, all_text, entries)
        for fp, text in all_text.items():
            target_findings.extend(detect_in_file(fp, text, entries))
        by_target[str(target)] = target_findings

    # Same (rule_id, resource_name, file_base) tuple across >1 target.
    # Use sets so the same finding repeated in one repo only counts
    # once per repo for the cross-repo correlation.
    sig_targets: dict[tuple, set[str]] = {}
    for tgt, fs in by_target.items():
        for f in fs:
            sig = (f["id"], f.get("resource", ""), f.get("file", "").rsplit("/", 1)[-1])
            sig_targets.setdefault(sig, set()).add(tgt)

    fleet_wide: list[dict] = []
    seen_fleet: set[tuple] = set()
    for tgt, fs in by_target.items():
        for f in fs:
            sig = (f["id"], f.get("resource", ""), f.get("file", "").rsplit("/", 1)[-1])
            repos = list(sig_targets.get(sig, set()))
            if len(repos) > 1 and sig not in seen_fleet:
                seen_fleet.add(sig)
                fleet_wide.append({
                    **f,
                    "fleet_count": len(repos),
                    "fleet_repos": repos,
                })

    return {
        "by_target": by_target,
        "fleet_wide": fleet_wide,
        "summary": {t: len(fs) for t, fs in by_target.items()},
    }


def render_fleet_report(fleet_result: dict, fmt: str) -> str:
    """Render fleet scan results as markdown table or JSON."""
    if fmt == "json":
        return json.dumps(fleet_result, indent=2, default=str)

    lines: list[str] = ["# Fleet Scan Report\n"]
    lines.append("## Per-Repo Summary\n")
    lines.append("| Repository | Findings |")
    lines.append("|---|---|")
    for tgt, count in fleet_result["summary"].items():
        lines.append(f"| `{tgt}` | {count} |")

    fleet_wide = fleet_result.get("fleet_wide", [])
    lines.append(f"\n## Fleet-Wide Findings ({len(fleet_wide)} across multiple repos)\n")
    if fleet_wide:
        lines.append("| Rule | Resource | Count | Repos |")
        lines.append("|---|---|---|---|")
        for f in fleet_wide:
            repos_short = ", ".join(r.rsplit("/", 1)[-1] for r in f.get("fleet_repos", []))
            lines.append(
                f"| {f['id']} | `{f.get('resource','')}` | "
                f"{f.get('fleet_count',0)} | {repos_short} |"
            )
    else:
        lines.append("_No findings appear in more than one repository._")

    lines.append("\n## Per-Repo Findings\n")
    for tgt, fs in fleet_result["by_target"].items():
        lines.append(f"### `{tgt}` ({len(fs)} finding{'s' if len(fs) != 1 else ''})\n")
        for f in fs[:50]:  # cap per-repo lines to keep the report skim-able
            lines.append(
                f"- `{f['id']}` "
                f"{f.get('file','').rsplit('/',2)[-1]}:{f.get('line','')} "
                f"`{f.get('resource','')}`"
            )
        if len(fs) > 50:
            lines.append(f"- _...and {len(fs)-50} more_")
        lines.append("")

    return "\n".join(lines)


def trend_get_commits(target: Path, lookback_days: int) -> list[tuple[str, str]]:
    """Return ``(sha, date)`` pairs for commits touching .tf files, oldest first."""
    result = subprocess.run(
        ["git", "log", "--format=%H %as", f"--since={lookback_days} days ago",
         "--reverse", "--", "*.tf"],
        capture_output=True, text=True, cwd=str(target),
    )
    if result.returncode != 0:
        return []
    pairs: list[tuple[str, str]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2:
            pairs.append((parts[0], parts[1].strip()))
    return pairs


def trend_tf_files_at_sha(target: Path, sha: str) -> list[str]:
    """List .tf files tracked at a given commit SHA."""
    result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", sha],
        capture_output=True, text=True, cwd=str(target),
    )
    return [p for p in result.stdout.strip().splitlines() if p.endswith(".tf")]


def trend_scan_at_sha(
    target: Path,
    sha: str,
    entries: list[dict],
    *,
    detect_in_file: Callable[[Path, str, list], list[dict]],
) -> set[tuple[str, str, int]]:
    """``(rule_id, rel_path, line)`` tuples for a commit SHA.

    Reads file content via ``git show`` so the working tree isn't
    touched — the user can run trend mode against history without
    checkout interference.
    """
    findings_set: set[tuple[str, str, int]] = set()
    for rel_path in trend_tf_files_at_sha(target, sha):
        show = subprocess.run(
            ["git", "show", f"{sha}:{rel_path}"],
            capture_output=True, text=True, cwd=str(target),
        )
        if show.returncode != 0:
            continue
        text = show.stdout
        fake_path = target / rel_path
        try:
            for f in detect_in_file(fake_path, text, entries):
                findings_set.add((f["id"], rel_path, f.get("line", 0)))
        except Exception:
            continue
    return findings_set


def run_trend(
    target: Path,
    entries: list[dict],
    lookback_days: int,
    *,
    detect_in_file: Callable[[Path, str, list], list[dict]],
) -> list[dict]:
    """Walk git history and compute per-commit finding deltas."""
    commits = trend_get_commits(target, lookback_days)
    if not commits:
        return []
    rows: list[dict] = []
    prev: set[tuple[str, str, int]] = set()
    for sha, date in commits:
        curr = trend_scan_at_sha(target, sha, entries, detect_in_file=detect_in_file)
        new_count = len(curr - prev)
        resolved = len(prev - curr)
        rows.append({
            "date": date,
            "sha": sha[:8],
            "new": new_count,
            "resolved": resolved,
            "net": new_count - resolved,
            "total": len(curr),
        })
        prev = curr
    return rows


def render_trend_table(rows: list[dict], fmt: str) -> str:
    """Render trend rows as markdown table or JSON."""
    if fmt == "json":
        return json.dumps(rows, indent=2)
    if not rows:
        return "_No commits touching .tf files found in the specified lookback window._"
    lines = [
        "# Risk Trend\n",
        "| Date | SHA | New | Resolved | Net | Total |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        net_str = f"+{r['net']}" if r["net"] > 0 else str(r["net"])
        lines.append(
            f"| {r['date']} | `{r['sha']}` | +{r['new']} | -{r['resolved']} | "
            f"{net_str} | {r['total']} |"
        )
    total_new = sum(r["new"] for r in rows)
    total_res = sum(r["resolved"] for r in rows)
    net = total_new - total_res
    net_str = f"+{net}" if net > 0 else str(net)
    lines.append(
        f"\n**{len(rows)} commits analysed. Net change: {net_str} "
        f"({total_new} introduced, {total_res} resolved).**"
    )
    return "\n".join(lines)
