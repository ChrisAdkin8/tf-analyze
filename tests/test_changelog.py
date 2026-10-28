"""Changelog fragments are assembled into CHANGELOG.md.

Every PR used to add its `## Round N` section at the top of CHANGELOG.md,
so open PRs conflicted with each other and claimed the same round number.
Now each PR adds `changelog.d/<name>.md` and `scripts/changelog.py build`
numbers and moves them.
"""

from __future__ import annotations

from pathlib import Path

import changelog
import pytest

HEADER = """# Changelog

Rule counts are as of each round's commit.

---

## Round 82 — Older entry — 2026-10-28

- old text
"""


def _setup(tmp_path: Path, fragments: dict[str, str]) -> tuple[Path, Path]:
    log = tmp_path / "CHANGELOG.md"
    log.write_text(HEADER, encoding="utf-8")
    frag_dir = tmp_path / "changelog.d"
    frag_dir.mkdir()
    (frag_dir / "README.md").write_text("# not a fragment\n", encoding="utf-8")
    for name, text in fragments.items():
        (frag_dir / name).write_text(text, encoding="utf-8")
    return log, frag_dir


def test_build_numbers_rounds_and_puts_newest_first(tmp_path: Path) -> None:
    log, frag_dir = _setup(
        tmp_path,
        {
            "a-first.md": "## First change\n\n- one\n",
            "b-second.md": "## Second change\n\n- two\n",
        },
    )
    headings = changelog.build(log, frag_dir, date="2026-11-01")

    assert headings == [
        "## Round 84 — Second change — 2026-11-01",
        "## Round 83 — First change — 2026-11-01",
    ]
    text = log.read_text(encoding="utf-8")
    assert text.index("Round 84") < text.index("Round 83") < text.index("Round 82")
    assert (
        "---\n\n## Round 84 — Second change — 2026-11-01\n\n- two\n\n## Round 83"
        in text
    )
    assert "- one\n\n## Round 82 — Older entry" in text
    # Fragments are consumed; the README stays.
    assert [p.name for p in frag_dir.iterdir()] == ["README.md"]


def test_build_with_no_fragments_leaves_changelog_alone(tmp_path: Path) -> None:
    log, frag_dir = _setup(tmp_path, {})
    assert changelog.build(log, frag_dir) == []
    assert log.read_text(encoding="utf-8") == HEADER


def test_build_refuses_a_malformed_fragment(tmp_path: Path) -> None:
    log, frag_dir = _setup(tmp_path, {"bad.md": "no heading\n"})
    with pytest.raises(SystemExit):
        changelog.build(log, frag_dir)
    assert log.read_text(encoding="utf-8") == HEADER
    assert (frag_dir / "bad.md").exists()


@pytest.mark.parametrize(
    "text, problem",
    [
        ("- no heading\n", "`## Title`"),
        ("## Round 83 — Title\n\n- x\n", "Round N"),
        ("## Title — 2026-10-28\n\n- x\n", "date"),
        ("## Title\n", "no text"),
        ("## Title\n\n- x\n\n## Another\n\n- y\n", "`###`"),
    ],
)
def test_malformed_fragments_are_reported(
    tmp_path: Path, text: str, problem: str
) -> None:
    path = tmp_path / "frag.md"
    path.write_text(text, encoding="utf-8")
    frag, errors = changelog.parse_fragment(path)
    assert frag is None
    assert any(problem in e for e in errors), errors


def test_well_formed_fragment_parses(tmp_path: Path) -> None:
    path = tmp_path / "frag.md"
    path.write_text("## A title\n\n- body\n\n### Detail\n\nmore\n", encoding="utf-8")
    frag, errors = changelog.parse_fragment(path)
    assert errors == []
    assert frag is not None
    assert frag.title == "A title"
    assert frag.body == "- body\n\n### Detail\n\nmore"


def test_repo_fragments_are_well_formed() -> None:
    assert changelog.check_fragments() == []
