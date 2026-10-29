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
* :func:`inline_ignore_markers` / :func:`trusted_inline_markers` — the
  same comments with the code they cover, and the subset a trusted git
  ref also has (``--inline-ignores-from``).
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
from typing import Callable, NamedTuple


def load_suppressions(
    target: Path,
    *,
    load_yaml: Callable[[str], dict],
    ignore_file: Path | None = None,
) -> tuple[dict, dict]:
    """Read ``.tf-analyze-ignore.yaml`` and return ``(active, expired)``.

    Both dicts map rule_id → ``{"reason": str, "expires": str|None}``.
    Expired suppressions are not silently dropped; the caller can use
    them to label findings that *were* previously suppressed but are
    now active because the expiry date has passed.
    """
    active: dict[str, dict] = {}
    expired: dict[str, dict] = {}
    if ignore_file is not None:
        # An explicit file replaces the lookup: missing means "none".
        if not ignore_file.is_file():
            return active, expired
    elif not (ignore_file := target / ".tf-analyze-ignore.yaml").exists():
        parent_ignore = target.parent / ".tf-analyze-ignore.yaml"
        if parent_ignore.exists():
            ignore_file = parent_ignore
        else:
            return active, expired

    try:
        data = load_yaml(ignore_file.read_text(encoding="utf-8-sig"))
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
    source: str | None = None,
) -> dict[int, set[str]]:
    """Find ``# tf-analyze:ignore <ID>`` comments and return ``line → {ids}``.

    Each ID suppresses the line the comment is on. A comment on a line
    with no code at all also suppresses the next line, so it can sit
    above the block or argument it silences. A comment on a line that has
    code, before or after it (``key = "x" # tf-analyze:ignore ID``,
    ``/* tf-analyze:ignore ID */ key = "x"``), covers only that line: it
    used to cover the next line too, silencing a finding there that
    nobody marked.

    ``source`` is the file's text when ``text`` is a comments-only copy
    of it (everything else blanked, columns kept): the line's code is
    read from it. Without it, ``text`` is the source itself.
    """
    src_lines = source.split("\n") if source is not None else None
    result: dict[int, set[str]] = {}
    for i, line in enumerate(text.split("\n"), 1):
        m = inline_ignore_re.search(line)
        if m:
            result.setdefault(i, set()).add(m.group(1))
            if src_lines is not None and i <= len(src_lines):
                code = _line_code(src_lines[i - 1], line)
            else:
                code = line[:m.start()]
            if not code.strip():
                result.setdefault(i + 1, set()).add(m.group(1))
    return result


def _line_code(orig: str, com: str) -> str:
    """``orig`` with its comments blanked: ``com`` is the comments-only
    copy of the same line (comment characters kept, columns kept)."""
    return "".join(o if k >= len(com) or com[k].isspace() else " "
                   for k, o in enumerate(orig))


class InlineMarker(NamedTuple):
    """One inline ignore: where it is, which rule, the code it covers
    (``anchor``) and whether it sits on a line of its own (``standalone``,
    so it also covers the next line)."""

    line: int
    rule_id: str
    anchor: str
    standalone: bool


def inline_ignore_markers(
    text: str,
    comment_text: str,
    *,
    inline_ignore_re: re.Pattern,
) -> list[InlineMarker]:
    """Every inline ignore in ``text`` as an :class:`InlineMarker`.

    ``comment_text`` is ``text`` with everything but comments blanked to
    spaces (same length, same newlines), so a marker inside a string or a
    heredoc is not one. ``standalone`` follows
    :func:`load_inline_suppressions`: the marker's line has no code.

    The *anchor* is the code the ignore covers, comments left out and
    whitespace normalised. The covered line is the marker's own line if
    it has code, else (``standalone``) the next line that has code. If
    the covered line opens a block (its code ends in ``{``), the anchor
    is the whole block, so any change inside it drops a trusted ignore
    on the block (a finding reported on a ``resource`` line covers the
    whole resource). Otherwise it is that one line. It does not depend
    on line numbers, so lines added or removed elsewhere in the file
    leave it unchanged (see :func:`trusted_inline_markers`).
    """
    lines = text.split("\n")
    clines = comment_text.split("\n")
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln) + 1)

    def raw_code(i: int) -> str:
        if i >= len(lines):
            return ""
        return _line_code(lines[i], clines[i] if i < len(clines) else "")

    def code(i: int) -> str:
        return " ".join(raw_code(i).split())

    def block_anchor(i: int) -> str:
        line = raw_code(i)
        if not line.rstrip().endswith("{"):
            return code(i)
        from _hcl import brace_walk  # local: keep this module light

        end = brace_walk(text, offsets[i] + line.rstrip().rfind("{"))
        if end is None:
            return code(i)
        last = max(k for k in range(i, len(lines)) if offsets[k] < end)
        return " ".join(" ".join(code(k) for k in range(i, last + 1)).split())

    markers: list[InlineMarker] = []
    for i, cline in enumerate(clines):
        m = inline_ignore_re.search(cline)
        if not m:
            continue
        standalone = not code(i)
        covered = i
        while covered < len(lines) and not code(covered):
            covered += 1
        anchor = block_anchor(covered) if covered < len(lines) else ""
        markers.append(InlineMarker(i + 1, m.group(1), anchor, standalone))
    return markers


def markers_to_suppressions(markers: list[InlineMarker]) -> dict[int, set[str]]:
    """``line → {ids}`` for :func:`apply_suppressions`, with the same reach
    as :func:`load_inline_suppressions`: the marker's line, and the next
    one too for a comment on a line of its own."""
    result: dict[int, set[str]] = {}
    for mk in markers:
        result.setdefault(mk.line, set()).add(mk.rule_id)
        if mk.standalone:
            result.setdefault(mk.line + 1, set()).add(mk.rule_id)
    return result


def trusted_inline_markers(
    head: list[InlineMarker],
    base: list[InlineMarker] | None,
) -> tuple[list[InlineMarker], list[InlineMarker]]:
    """Split ``head``'s inline ignores into ``(trusted, dropped)`` against
    the same file's ignores at a trusted ref (``base``; ``None`` when the
    file isn't there, so nothing is trusted).

    A head ignore is trusted when the base has one for the same rule on
    the same anchor. Matching is count-aware: if the base has N ignores
    for a (rule, anchor), at most N head ones are trusted, so copying an
    accepted marker onto another identical line does not suppress both.
    """
    if not base:
        return [], list(head)
    budget: dict[tuple[str, str], int] = {}
    for mk in base:
        budget[(mk.rule_id, mk.anchor)] = budget.get((mk.rule_id, mk.anchor), 0) + 1
    trusted: list[InlineMarker] = []
    dropped: list[InlineMarker] = []
    for marker in head:
        key = (marker.rule_id, marker.anchor)
        if budget.get(key, 0) > 0:
            budget[key] -= 1
            trusted.append(marker)
        else:
            dropped.append(marker)
    return trusted, dropped


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
        data = json.loads(path.read_text(encoding="utf-8-sig"))
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
    default_urgency: dict[str, str] | None = None,
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

    A current finding is compared at its urgency before
    ``--attack-graph`` moved it (``_urgency_before_graph``), so turning the
    graph on, or the graph's view changing, does not un-suppress it.

    A baseline finding with no ``urgency`` (an old report, or a
    hand-written one) counts as its rule's catalogue default
    (`default_urgency`, rule id -> urgency), or as the lowest tier when
    the rule is unknown: it still suppresses the same finding at its
    default urgency, but cannot hide one that was escalated above it.

    A missing or unreadable baseline returns ``(current, [])`` plus a
    stderr warning — better to surface noisily than silently pass.
    """
    loaded = _load_report(baseline_path, "baseline")
    if loaded is None:
        return current, []
    prior, prior_target = loaded
    paired, _ = _pair_findings(prior, current, prior_target or target, target)
    defaults = default_urgency or {}
    for ci, pi in list(paired.items()):
        was = _urgency_rank(prior[pi], defaults)
        now = _urgency_rank(current[ci], defaults)
        if now > was:
            del paired[ci]
    retained = [f for i, f in enumerate(current) if i not in paired]
    suppressed = [f for i, f in enumerate(current) if i in paired]
    return retained, suppressed


_URGENCY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _urgency_rank(finding: dict, defaults: dict[str, str] | None = None) -> int:
    """A finding's urgency as a number. One that carries none (an old
    report, or a finding not yet enriched) takes its rule's default from
    `defaults`, else the lowest tier (0): a missing urgency must never
    let a baseline entry hide a higher-urgency finding."""
    urgency = (
        finding.get("_urgency_before_graph")
        or finding.get("urgency")
        or (defaults or {}).get(finding.get("id"), "")
    )
    return _URGENCY_RANK.get(str(urgency).upper(), 0)


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
