"""Regression tests for the P2/P3 backlog fixes (engine correctness)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _baseline  # noqa: E402
import _hcl  # noqa: E402
import _output  # noqa: E402
import _scoring  # noqa: E402


def test_compare_reports_counts_duplicate_keys(tmp_path: Path) -> None:
    # Two findings sharing (id,file,resource) in prior; one is fixed. A set
    # collapsed them and reported "unchanged"; multiset semantics report the
    # resolution.
    prior = [
        {"id": "X", "file": "a.tf", "resource": "r", "line": 5},
        {"id": "X", "file": "a.tf", "resource": "r", "line": 9},
    ]
    cur = [{"id": "X", "file": "a.tf", "resource": "r", "line": 5}]
    pf = tmp_path / "prior.json"
    pf.write_text(json.dumps({"findings": prior}))
    d = _baseline.compare_reports(cur, pf)
    assert len(d["resolved"]) == 1
    assert len(d["unchanged"]) == 1
    assert len(d["new"]) == 0


def test_strip_hcl_context_is_string_aware() -> None:
    # `//` inside a double-quoted string is NOT a comment — the token after
    # it must survive (old regex blanked it).
    out = _hcl.strip_hcl_context('x = "http://foo"\nbad_token = 1\n')
    assert "bad_token" in out
    # A comment immediately after a closing quote IS stripped (old regex missed it).
    out2 = _hcl.strip_hcl_context('v = "x"# ignore_changes = all\n')
    assert "ignore_changes" not in out2
    # Pinned contract: length and every newline position preserved.
    src = 'a = 1 # c\n/* blk\n  comment */\nb = 2\n'
    stripped = _hcl.strip_hcl_context(src)
    assert len(stripped) == len(src)
    assert stripped.count("\n") == src.count("\n")
    assert "b = 2" in stripped


def test_md_cell_escapes_pipe_and_newline() -> None:
    assert _output._md_cell("a | b") == "a \\| b"
    assert "\n" not in _output._md_cell("a\nb\r\nc")


def test_score_floors_half_penalty() -> None:
    # One suppressed LOW → half-weight 0.5 → raw 99.5. floor → 99 (banker's
    # round-half-to-even gave 100, the surprising direction the fix removes).
    s = _scoring._compute_summary([], suppressed=[{"urgency": "LOW"}])
    assert s["score"] == 99
    assert "floor" in s["formula"]


def test_every_catalog_kind_is_dispatchable() -> None:
    # A typo'd `kind:` makes a rule silently never fire (the dispatch loops
    # do `.get(kind)` and skip on miss). Assert every catalog kind maps to a
    # registered handler — auto-tracks new handlers; the SPECIAL set covers
    # the four kinds dispatched by a branch in _handlers_robustness rather
    # than the decorator-registered dicts.
    import glob
    import re

    import detect  # noqa: E402

    valid = set(detect._INFILE_HANDLERS) | set(detect._CORPUS_HANDLERS) | {
        "prod_tag_force_destroy", "prod_tag_no_deletion_protection",
        "var_desc_must_no_validation", "var_name_false_default",
    }
    bad: dict[str, set] = {}
    for f in glob.glob(str(REPO_ROOT / "catalog" / "*.yaml")):
        for kind in re.findall(r"(?m)^\s*-?\s*kind:\s*(\w+)", Path(f).read_text()):
            if kind not in valid:
                bad.setdefault(Path(f).name, set()).add(kind)
    assert not bad, f"catalog rules with an unknown/undispatched kind (typo?): {bad}"
