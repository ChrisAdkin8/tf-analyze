"""A rule's own `fix_hcl` must not trigger that rule.

The `_clean` fixtures cover this for the kinds `gen_clean_fixtures.py`
can scaffold; this runs every rule with a `fix_hcl` (grep, module and
corpus kinds included), scanning the snippet alone against that one rule.

KNOWN_SELF_TRIGGERS is a ratchet: each entry is a real catalogue defect.
Fixing one makes its xfail pass, which fails the test (strict) until the
entry is removed — so the list can only shrink.
"""

from __future__ import annotations

from pathlib import Path

import detect
import pytest

REPO = Path(__file__).resolve().parents[1]
ENTRIES = [e for e in detect.load_catalog(REPO / "catalog") if e.get("fix_hcl")]

KNOWN_SELF_TRIGGERS: dict[str, str] = {}

# Fixes that are not a `.tf` file: rule id -> file name to write the
# snippet to (alongside an empty main.tf so the directory is a module).
FIX_FILE_NAME = {
    "CI-TEST-001": "main.tftest.hcl",
}


def _own_findings(entry: dict, tmp_path: Path) -> list[dict]:
    fix = entry["fix_hcl"]
    name = FIX_FILE_NAME.get(entry["id"], "main.tf")
    fp = tmp_path / name
    fp.write_text(fix)
    files = {fp: fix}
    if name != "main.tf":
        (tmp_path / "main.tf").write_text("")
        files[tmp_path / "main.tf"] = ""
    findings = detect.detect_corpus(tmp_path, files, [entry])
    for path, text in files.items():
        findings += detect.detect_in_file(path, text, [entry])
    return [f for f in findings if f["id"] == entry["id"]]


def _param(entry: dict):
    reason = KNOWN_SELF_TRIGGERS.get(entry["id"])
    marks = [pytest.mark.xfail(reason=reason, strict=True)] if reason else []
    return pytest.param(entry, id=entry["id"], marks=marks)


def test_known_list_names_real_rules() -> None:
    ids = {e["id"] for e in ENTRIES}
    assert set(KNOWN_SELF_TRIGGERS) <= ids
    assert set(FIX_FILE_NAME) <= ids


@pytest.mark.parametrize("entry", [_param(e) for e in ENTRIES])
def test_fix_hcl_does_not_trigger_its_rule(entry: dict, tmp_path: Path) -> None:
    fired = _own_findings(entry, tmp_path)
    assert not fired, (
        f"{entry['id']} fires on its own fix_hcl at line(s) "
        f"{sorted({f.get('line') or 0 for f in fired})}"
    )
