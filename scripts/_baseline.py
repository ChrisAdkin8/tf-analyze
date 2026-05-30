"""Suppressions, baseline, and report-comparison helpers.

Five pure-data functions extracted from ``detect.py`` as the **15th
modularisation seam**. None of them call out to subprocess or the
filesystem beyond reading the named input file — every other side
effect is the caller's responsibility.

* :func:`load_suppressions` — read ``.tf-analyze-ignore.yaml`` (in
  the target dir or its parent), return ``(active, expired)`` dicts.
* :func:`load_inline_suppressions` — find
  ``# tf-analyze:ignore <ID>`` comments inline in HCL text, return
  ``{line: {ids}}``.
* :func:`apply_suppressions` — split findings into active / suppressed
  using both inline and global suppression dicts.
* :func:`apply_baseline` — filter findings against a baseline JSON
  report; the ``(id, file, line, resource)`` tuple is the match key
  so the same finding moving lines counts as new.
* :func:`compare_reports` — pre-and-post diff of two findings lists;
  returns ``{resolved, new, unchanged}``. Match key is
  ``(id, file, resource)`` (line excluded) so refactors that preserve
  semantics don't flip findings into resolved+new pairs.

The inline-suppression regex and the YAML loader are injected by the
caller (``detect.py``) to avoid pulling in detect.py-internal grammar.
"""
from __future__ import annotations

import datetime
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Callable


def load_suppressions(
    target: Path,
    *,
    load_yaml: Callable[[str], dict],
) -> tuple[dict, dict]:
    """Read ``.tf-analyze-ignore.yaml`` and return ``(active, expired)``.

    Both dicts map rule_id → ``{"reason": str, "expires": str|None}``.
    Expired suppressions are not silently dropped; the caller can use
    them to label findings that *were* previously suppressed but are
    now active because the expiry date has passed.
    """
    active: dict[str, dict] = {}
    expired: dict[str, dict] = {}
    ignore_file = target / ".tf-analyze-ignore.yaml"
    if not ignore_file.exists():
        parent_ignore = target.parent / ".tf-analyze-ignore.yaml"
        if parent_ignore.exists():
            ignore_file = parent_ignore
        else:
            return active, expired

    try:
        data = load_yaml(ignore_file.read_text())
        for item in data.get("suppressions") or []:
            sid = item.get("id", "")
            if not sid:
                continue
            entry = {
                "reason": item.get("reason", ""),
                "expires": item.get("expires"),
            }
            expires = entry["expires"]
            if expires:
                try:
                    exp_date = datetime.date.fromisoformat(str(expires))
                    if exp_date < datetime.date.today():
                        expired[sid] = entry
                        continue
                except ValueError as date_err:
                    # Malformed date — surface loudly rather than
                    # silently treating the suppression as active.
                    # Round-5 audit fix #13 — include the parser's
                    # error message so the operator sees both the
                    # offending value AND the specific complaint
                    # (e.g. "month out of range" vs "wrong format")
                    # and an explicit hint about zero-padding.
                    print(
                        f"WARN: suppression {sid} has malformed "
                        f"expires={expires!r} ({date_err}); treating as active. "
                        f"Use zero-padded ISO date YYYY-MM-DD "
                        f"(e.g. 2026-05-11, not 2026-5-11).",
                        file=sys.stderr,
                    )
            active[sid] = entry
    except Exception as e:
        print(f"WARN: failed to load {ignore_file}: {e}", file=sys.stderr)
    return active, expired


def load_inline_suppressions(
    text: str,
    *,
    inline_ignore_re: re.Pattern,
) -> dict[int, set[str]]:
    """Find ``# tf-analyze:ignore <ID>`` comments and return ``line → {ids}``.

    Each ID suppresses both the line the comment is on *and* the
    next line — so the comment can sit above a block that the next
    line opens.
    """
    result: dict[int, set[str]] = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = inline_ignore_re.search(line)
        if m:
            result.setdefault(i, set()).add(m.group(1))
            result.setdefault(i + 1, set()).add(m.group(1))
    return result


def apply_suppressions(
    findings: list[dict],
    file_suppressions: dict,
    global_suppressions: dict,
) -> tuple[list[dict], list[dict]]:
    """Split findings into ``(active, suppressed)`` lists."""
    active: list[dict] = []
    suppressed: list[dict] = []
    for f in findings:
        fid = f["id"]
        if fid in global_suppressions:
            f["suppression_reason"] = global_suppressions[fid].get("reason", "")
            suppressed.append(f)
            continue
        fline = f.get("line", 0)
        ffile = f.get("file", "")
        inline = file_suppressions.get(ffile, {})
        if fline in inline and fid in inline[fline]:
            f["suppression_reason"] = "inline comment"
            suppressed.append(f)
            continue
        active.append(f)
    return active, suppressed


def apply_baseline(
    current: list[dict],
    baseline_path: Path,
) -> tuple[list[dict], list[dict]]:
    """Filter ``current`` findings against a baseline JSON report.

    Returns ``(retained, suppressed)``:

    * ``retained`` — new or still-broken findings; affect the exit
      code under ``--fail-on``.
    * ``suppressed`` — findings that were in the baseline.

    Match key is ``(id, file, line, resource)`` so the same rule
    moving lines counts as new (the user can re-baseline if that
    line change is intentional).

    A missing or unreadable baseline returns ``(current, [])`` plus a
    stderr warning — better to surface noisily than silently pass.
    """
    try:
        data = json.loads(baseline_path.read_text())
        prior = data if isinstance(data, list) else data.get("findings", [])
    except Exception as e:
        print(f"WARN: cannot load baseline {baseline_path}: {e}", file=sys.stderr)
        return current, []
    prior_keys = {
        (f.get("id"), f.get("file", ""), f.get("line", 0), f.get("resource", ""))
        for f in prior
    }
    retained: list[dict] = []
    suppressed: list[dict] = []
    for f in current:
        key = (f.get("id"), f.get("file", ""), f.get("line", 0), f.get("resource", ""))
        if key in prior_keys:
            suppressed.append(f)
        else:
            retained.append(f)
    return retained, suppressed


def compare_reports(current: list[dict], prior_path: Path) -> dict:
    """Compare current findings against a prior JSON report.

    Returns ``{resolved: [...], new: [...], unchanged: [...]}``.
    Match key omits ``line`` so a finding that moved by a line
    doesn't appear as both *resolved* and *new* — only genuinely
    new/removed findings flip status.
    """
    try:
        data = json.loads(prior_path.read_text())
        if isinstance(data, list):
            prior_findings = data
        else:
            prior_findings = data.get("findings", [])
    except Exception as e:
        print(f"WARN: cannot load prior report {prior_path}: {e}", file=sys.stderr)
        return {"resolved": [], "new": list(current), "unchanged": []}

    # Multiset (counted) semantics — a set collapsed N same-(id,file,resource)
    # findings into one, so fixing one of two identical-key findings showed
    # as "unchanged" and the resolution was never reported. Count keys and
    # match min(prior,cur) as unchanged, the surplus on each side as
    # resolved/new.
    def _key(f: dict) -> tuple:
        return (f["id"], f.get("file", ""), f.get("resource", ""))

    prior_count = Counter(_key(f) for f in prior_findings)
    cur_count = Counter(_key(f) for f in current)

    resolved, new, unchanged = [], [], []
    seen: Counter = Counter()
    for f in prior_findings:
        k = _key(f)
        seen[k] += 1
        # Surplus prior occurrences (beyond what current still has) resolved.
        if seen[k] > cur_count[k]:
            resolved.append(f)
    seen = Counter()
    for f in current:
        k = _key(f)
        seen[k] += 1
        # First min(prior,cur) current occurrences are matched (unchanged);
        # the surplus is genuinely new.
        if seen[k] <= prior_count[k]:
            unchanged.append(f)
        else:
            new.append(f)
    return {"resolved": resolved, "new": new, "unchanged": unchanged}
