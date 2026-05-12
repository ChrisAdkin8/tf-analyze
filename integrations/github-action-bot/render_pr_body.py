#!/usr/bin/env python3
"""Compose the PR body for the tf-analyze auto-remediation bot (R31.2).

The bot workflow at integrations/github-action-bot.yml shells out to
this script after a successful `--apply-fixes apply`. The script reads
the *pre-fix* scan JSON + the captured apply-fixes stderr summary,
groups findings by rule family (the id prefix up to the second hyphen,
e.g. ``SEC-AWS-IAM-001`` → ``SEC-AWS-IAM``), and emits a Markdown body
the workflow passes to ``gh pr create --body-file``.

Kept as a separate script (rather than embedded in the YAML) so the
body shape can be unit-tested without standing up a real GitHub
Actions environment — see tests/test_github_action_bot.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def family_of(rule_id: str) -> str:
    """Return the family prefix used to group findings in the PR body.

    Rule ids look like ``SEC-AWS-IAM-001`` / ``ROB-COUNT-NAME-002``.
    The family is everything up to (but not including) the final
    numeric segment — so the trailing ``-001`` is dropped, leaving
    ``SEC-AWS-IAM`` / ``ROB-COUNT-NAME``. This matches the family-
    backlinks generator on the per-rule docs site so the grouping
    feels consistent across surfaces.
    """
    parts = rule_id.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return rule_id


def compose_body(scan: dict, apply_summary: str) -> str:
    """Return the Markdown body of the bot's PR.

    Inputs:
      * ``scan`` — full JSON from `detect.py --target . --format json`,
        captured BEFORE apply-fixes ran. Has ``summary.score`` and the
        full ``findings`` list.
      * ``apply_summary`` — the engine's stderr lines starting with
        ``# apply-fixes:`` from the apply run. Strings like
        ``# apply-fixes: skipping 3 finding(s) above disruption cap 'none'``
        and ``# apply-fixes: would apply 1 fix(es) across 2 file(s)``.

    The body has four sections:
      1. **Headline** — score delta + count.
      2. **By family** — table of fixed rule-id-prefix → count.
      3. **Skipped** — fixes the bot intentionally avoided (above the
         disruption cap), so reviewers see the work *not* taken.
      4. **Provenance** — automation footer.
    """
    summary = scan.get("summary") or {}
    findings = scan.get("findings") or []
    score = summary.get("score", "?")
    grade = summary.get("grade", "?")

    # Group only the findings the bot would actually have patched
    # (fix_disruption == none). The engine has already filtered to
    # those; we re-derive the count from the apply summary for the
    # by-family table.
    fixable = [f for f in findings if f.get("fix_disruption") in (None, "none")]
    by_family: dict[str, list[dict]] = defaultdict(list)
    for f in fixable:
        by_family[family_of(f["id"])].append(f)

    # Parse the "would apply N fix(es) across M file(s)" line for the
    # headline. Falls back to fixable-count if the line is absent.
    n_applied = len(fixable)
    n_files = 0
    n_skipped = 0
    for line in (apply_summary or "").splitlines():
        s = line.strip()
        if "would apply" in s:
            # `# apply-fixes: would apply 5 fix(es) across 3 file(s)`
            try:
                tokens = s.split()
                n_applied = int(tokens[tokens.index("apply") + 1])
                n_files = int(tokens[tokens.index("across") + 1])
            except (ValueError, IndexError):
                pass
        elif "skipping" in s and "disruption" in s:
            try:
                tokens = s.split()
                n_skipped = int(tokens[tokens.index("skipping") + 1])
            except (ValueError, IndexError):
                pass

    lines: list[str] = [
        f"## tf-analyze auto-remediation",
        "",
        f"This PR applies **{n_applied} non-disruptive fix(es)** across "
        f"{n_files} file(s). Each fix comes from `fix_hcl` in the rule "
        f"catalogue and is restricted to `fix_disruption: none` — "
        f"changes that don't force resource replacement and don't "
        f"require `terraform plan` review for safety.",
        "",
        f"Pre-fix score: **{score} ({grade})**. Re-run the scanner "
        f"after merging to see the updated score.",
        "",
        "### Fixes by rule family",
        "",
    ]
    if by_family:
        lines.append("| Family | Fixes applied |")
        lines.append("|---|---|")
        for family in sorted(by_family):
            lines.append(f"| `{family}-*` | {len(by_family[family])} |")
    else:
        lines.append("_(No families to enumerate — apply-summary parsed as empty.)_")
    lines.append("")

    if n_skipped:
        lines.extend([
            "### Intentionally skipped",
            "",
            f"{n_skipped} additional finding(s) had a `fix_disruption` tier "
            f"above the bot's cap (`none`). Review the next tf-analyze scan "
            f"report for those; they require manual review or a higher cap.",
            "",
        ])

    lines.extend([
        "### Provenance",
        "",
        "- Bot workflow: `.github/workflows/tf-analyze-bot.yml`",
        "- Engine: [tf-analyze](https://github.com/ChrisAdkin8/tf-analyze)",
        "- Catalogue rules + `fix_hcl` snippets: same engine that ran in CI",
        "- Branch: `tf-analyze-bot/auto-fixes` (force-pushed; the bot "
        "reuses this branch on every run to avoid PR sprawl)",
        "",
        "Close this PR to opt out for one cycle; the bot will retry on "
        "its next scheduled run. To disable entirely, remove the workflow "
        "file.",
    ])
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan-json", type=Path, required=True,
                    help="Path to the pre-fix scan JSON (from --format json)")
    ap.add_argument("--apply-summary", type=Path, required=True,
                    help="Path to the captured `# apply-fixes:` stderr lines")
    ap.add_argument("--output", type=Path, required=True,
                    help="Path to write the Markdown body to")
    args = ap.parse_args()

    try:
        scan = json.loads(args.scan_json.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read scan JSON: {e}", file=sys.stderr)
        return 1
    try:
        apply_summary = args.apply_summary.read_text()
    except FileNotFoundError:
        apply_summary = ""
    body = compose_body(scan, apply_summary)
    args.output.write_text(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
