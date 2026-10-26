"""Parser migration Step 5: `block_arg_value` is top-level only.

Before Step 5 it returned the first ``arg = ...`` at *any* depth (an
instrumented run over every fixture and example found exactly one call
site where that mattered: `_resource_is_count_zero` reading a Cloud Armor
``rate_limit_threshold { count = 100 }`` as the resource's ``count``), and
in any body containing a heredoc it returned only the first element of a
list value. These tests pin both fixes and check `block_arg_value` against
the parse tree for every literal top-level setting in the corpus.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _hcl  # noqa: E402
import detect  # noqa: E402


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    """Compares against the parse tree, so it needs the real parser even in
    the CI job that forces the regex fallback."""
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


BODY = (
    '  rule {\n    count = 0\n  }\n'
    '  name = "x" # trailing comment\n'
    '  tags = {\n    count = 3\n  }\n'
    '  list = [\n    "a",\n    "*",\n  ]\n'
    '  doc = <<EOT\ncount = 9\nEOT\n'
    '  logging {\n    x = 1\n  }\n'
)


def test_top_level_only() -> None:
    assert _hcl.block_arg_value(BODY, "count") is None   # nested block / map / heredoc text
    assert _hcl.block_arg_value(BODY, "name") == "x"
    assert _hcl.block_arg_value(BODY, "logging") is None  # a block, not a value


def test_list_value_in_a_body_with_a_heredoc_is_complete() -> None:
    """The heredoc path used to return `val[0]` for lists, so e.g. an
    `actions = [..., "*"]` lost its wildcard whenever the body also held a
    heredoc."""
    assert _hcl.block_arg_value(BODY, "list") == '["a", "*"]'
    assert _hcl.block_arg_value(BODY, "doc") == "count = 9"


def test_nested_count_is_not_the_resource_count() -> None:
    body = '  rate_limit_threshold {\n    count = 0\n  }\n  name = "p"\n'
    assert not detect._resource_is_count_zero(body, {})
    assert detect._resource_is_count_zero('  count = 0\n' + body, {})


def _norm(s: str | None) -> str | None:
    if s is None:
        return None
    s = s.replace('\\"', '"')
    out, in_q, prev = [], False, ""
    for ch in s:
        if ch == '"' and prev != "\\":
            in_q = not in_q
        if in_q or not ch.isspace():
            out.append(ch)
        prev = ch
    return re.sub(r",([\]}])", r"\1", "".join(out))


def _literal(v) -> bool:
    scalar = (str, int, float, bool)
    if isinstance(v, str):
        # Expressions (`${...}`) other than a bare reference are rendered
        # differently by hcl2 (multi-line calls, dropped inner quotes).
        expr = _hcl.single_interpolation(v)
        return "\n" not in v and (expr is None or "(" not in expr)
    return v is None or isinstance(v, scalar) or (
        isinstance(v, list) and all(isinstance(x, scalar) for x in v)
    )


def test_block_arg_value_matches_the_tree_on_every_fixture() -> None:
    checked, bad = 0, []
    for corpus in ("fixtures", "examples"):
        for tf in sorted((REPO_ROOT / corpus).rglob("*.tf")):
            text = _hcl._read_normalized(tf)
            tree, _ = _hcl.parse_tf(text)
            if tree is None:
                continue
            subtrees = _hcl.resource_subtrees(tree)
            for blk in _hcl.find_blocks(text, detect.RESOURCE_START):
                found = subtrees.get(tuple(blk["groups"]), [])
                if len(found) != 1:
                    continue
                for key, value in found[0].items():
                    if key.startswith("__") or not _literal(value):
                        continue
                    checked += 1
                    old = _hcl.block_arg_value(blk["body"], key)
                    new = _hcl.render_hcl(value)
                    if _norm(old) == _norm(new):
                        continue
                    if old is not None and _hcl.single_interpolation(old) == new:
                        continue  # quoted "${var.x}" vs bare var.x
                    bad.append(f"{tf.relative_to(REPO_ROOT)} {'.'.join(blk['groups'])} "
                               f"{key}: text={old!r} tree={new!r}")
    assert checked > 2000
    assert not bad, "\n".join(bad[:20])


# ---- count = 0 skips only literals (spec §14 item 25) ------------------------

def test_literal_count_zero_skips() -> None:
    assert detect._resource_is_count_zero('  count = 0\n', {})
    assert detect._resource_is_count_zero('  count = false ? 1 : 0\n', {})


def test_count_from_a_variable_default_is_still_checked() -> None:
    """tfvars / -var can override a default at apply time, so a resource
    whose count resolves to 0 only through a default is not skipped."""
    vd = {"enabled": "false", "n": "0", "__local__n": "0"}
    assert not detect._resource_is_count_zero('  count = var.enabled ? 1 : 0\n', vd)
    assert not detect._resource_is_count_zero('  count = var.n\n', vd)
    assert not detect._resource_is_count_zero('  count = local.n\n', vd)
    assert not detect._resource_is_count_zero('  count = 1\n', vd)
