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
  report.
* :func:`compare_reports` — pre-and-post diff of two findings lists;
  returns ``{resolved, new, unchanged}``.

Both pair findings by rule, target-relative file and resource — never
the line — so code moving, or the repo being checked out elsewhere,
does not turn a known finding into a new one (`_pair_findings`).

The inline-suppression regex and the YAML loader are injected by the
caller (``detect.py``) to avoid pulling in detect.py-internal grammar.
"""
from __future__ import annotations

import datetime
import json
import re
import sys
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


def _relative_file(file: str, target: Path | None) -> str:
    """A finding's file relative to the scan `target` (POSIX form), so a
    baseline made in one checkout matches a scan of another. A path
    outside `target`, or with no target, is returned as-is."""
    file = (file or "").replace("\\", "/")
    if not file or target is None:
        return file
    p = Path(file)
    if not p.is_absolute():
        return file
    for cand in (p, p.resolve()):
        for root in (target, target.resolve()):
            try:
                return cand.relative_to(root).as_posix()
            except ValueError:
                continue
    return file


_MODULE_RESOURCE_RE = re.compile(r'^<module:[^>]*>$')


def _resource_key(resource: str) -> str:
    """A finding's resource for pairing. Module-level findings name the
    module by its directory (``<module:repo>``), which changes with the
    checkout folder; the target-relative file already identifies the
    module, so the name is dropped."""
    return _MODULE_RESOURCE_RE.sub("<module>", resource or "")


def _load_report(path: Path, what: str) -> tuple[list[dict], Path | None] | None:
    """``(findings, target)`` from a JSON report (or a bare findings
    list); `target` is the scan target the report recorded, if any.
    None — with a stderr warning — when the file cannot be read."""
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"WARN: cannot load {what} {path}: {e}", file=sys.stderr)
        return None
    if isinstance(data, list):
        return data, None
    recorded = data.get("target")
    return data.get("findings", []), Path(recorded) if recorded else None


def _pair_findings(
    prior: list[dict], current: list[dict],
    prior_target: Path | None, target: Path | None,
) -> tuple[dict[int, int], set[int]]:
    """Pair prior and current findings that are the same finding; return
    ``({current index: paired prior index}, paired prior indices)``.

    Same finding = same rule, same file (relative to each report's
    target) and same resource (see `_resource_key`). The line is *not* part of it — code
    moving must not turn a known finding into a new one. When one key
    has several findings, an exact line match pairs first, then the
    nearest remaining line. A prior path that could not be made relative
    (an old report with no recorded target, from another checkout) still
    pairs when it ends with the current relative path.
    """
    groups: dict[tuple, list[tuple[int, int]]] = {}
    for i, f in enumerate(prior):
        key = (f.get("id"), _relative_file(f.get("file", ""), prior_target),
               _resource_key(f.get("resource", "")))
        groups.setdefault(key, []).append((f.get("line") or 0, i))
    unrelativised = [k for k in groups if k[1].startswith("/")]
    paired_cur: dict[int, int] = {}
    paired_prior: set[int] = set()
    order = sorted(range(len(current)), key=lambda i: current[i].get("line") or 0)
    for exact in (True, False):
        for ci in order:
            if ci in paired_cur:
                continue
            f = current[ci]
            rel = _relative_file(f.get("file", ""), target)
            key = (f.get("id"), rel, _resource_key(f.get("resource", "")))
            line = f.get("line") or 0

            def free(keys: list[tuple]) -> list[tuple[int, int]]:
                return [
                    (abs(pl - line), pi)
                    for k in keys for pl, pi in groups.get(k, [])
                    if pi not in paired_prior and (not exact or pl == line)
                ]

            candidates = free([key])
            if not candidates and not exact and rel and not rel.startswith("/"):
                candidates = free([
                    k for k in unrelativised
                    if k[0] == key[0] and k[2] == key[2]
                    and k[1].endswith("/" + rel)
                ])
            if candidates:
                _, pi = min(candidates)
                paired_cur[ci] = pi
                paired_prior.add(pi)
    return paired_cur, paired_prior


def apply_baseline(
    current: list[dict],
    baseline_path: Path,
    target: Path | None = None,
) -> tuple[list[dict], list[dict]]:
    """Filter ``current`` findings against a baseline JSON report.

    Returns ``(retained, suppressed)``:

    * ``retained`` — new or still-broken findings; affect the exit
      code under ``--fail-on``.
    * ``suppressed`` — findings that were in the baseline.

    Findings pair as in `_pair_findings`: rule, file relative to the
    scan `target` (the baseline's own recorded target for its side), and
    resource — not the line, so adding a line above a baselined finding
    or checking the repo out somewhere else does not make it "new".
    A paired finding whose urgency is now higher than the baseline's
    (e.g. a security group moving from port 443 to 22) is retained: the
    baseline accepted the old risk, not the worse one.

    A missing or unreadable baseline returns ``(current, [])`` plus a
    stderr warning — better to surface noisily than silently pass.
    """
    loaded = _load_report(baseline_path, "baseline")
    if loaded is None:
        return current, []
    prior, prior_target = loaded
    paired, _ = _pair_findings(prior, current, prior_target or target, target)
    for ci, pi in list(paired.items()):
        was, now = _urgency_rank(prior[pi]), _urgency_rank(current[ci])
        if was >= 0 and now > was:
            del paired[ci]
    retained = [f for i, f in enumerate(current) if i not in paired]
    suppressed = [f for i, f in enumerate(current) if i in paired]
    return retained, suppressed


_URGENCY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _urgency_rank(finding: dict) -> int:
    """A finding's urgency as a number; -1 when it carries none (an old
    report, or a finding not yet enriched). A baseline finding with no
    urgency is never compared, so old baselines keep suppressing."""
    return _URGENCY_RANK.get(str(finding.get("urgency") or "").upper(), -1)


def compare_reports(
    current: list[dict], prior_path: Path, target: Path | None = None,
) -> dict:
    """Compare current findings against a prior JSON report.

    Returns ``{resolved: [...], new: [...], unchanged: [...]}``, pairing
    findings as `apply_baseline` does (line excluded; duplicates of one
    key counted, so fixing one of two identical findings shows as
    resolved).
    """
    loaded = _load_report(prior_path, "prior report")
    if loaded is None:
        return {"resolved": [], "new": list(current), "unchanged": []}
    prior, prior_target = loaded
    paired_cur, paired_prior = _pair_findings(
        prior, current, prior_target or target, target,
    )
    return {
        "resolved": [f for i, f in enumerate(prior) if i not in paired_prior],
        "new": [f for i, f in enumerate(current) if i not in paired_cur],
        "unchanged": [f for i, f in enumerate(current) if i in paired_cur],
    }
