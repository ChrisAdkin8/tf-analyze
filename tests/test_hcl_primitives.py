"""Property-based tests for the HCL string-manipulation primitives.

The example-based fixture suite exercises the primitives only on the
inputs the test author thought of. The LSP server runs these primitives
on **every keystroke** — meaning a malformed-HCL crash on partially-
typed input is a freeze on the user's screen. ``hypothesis`` generates
adversarial inputs the example suite never thought to test.

Primitives covered:

  * ``_hcl_object_to_json(text)`` — HCL → Python dict converter, used
    inside ``jsonencode({...})`` analysis. Must return ``None`` rather
    than raise on any input.
  * ``block_arg_value(body, arg)`` — extract the literal value of an
    attribute from a resource body. Must not raise.
  * ``_resolve_var_ref(val, var_defaults)`` — resolve plain ``var.X``
    / ``local.X`` references and fold simple ternaries. Idempotent
    when no variable is known.
  * ``_expand_dynamic_blocks(body)`` — structural rewrite that flattens
    ``dynamic "X" { ... }`` blocks. Must not raise on truncated /
    unbalanced input. Output must contain no ``dynamic "`` headers.
  * ``find_blocks(text, regex)`` — top-level block locator. Must not
    raise on unbalanced braces, embedded strings, or partial input.

Default ``hypothesis`` profile is fast (50 examples per test); the
``thorough`` profile (1000 examples) runs in CI weekly via a separate
job.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

# Skip the whole module if hypothesis isn't installed — tests degrade
# gracefully on a stripped Python install.
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402

# Tighten the default budget to keep `pytest -q` fast. The "thorough"
# profile (1000 examples / longer deadlines) is reserved for the
# scheduled CI runs that catch the rarer crashers.
settings.register_profile("fast", max_examples=50, deadline=1000)
settings.register_profile("thorough", max_examples=1000, deadline=5000)
settings.load_profile("fast")


# ---------------------------------------------------------------------------
# Strategies — biased toward inputs that look like HCL but break the parsers
# ---------------------------------------------------------------------------

# Identifier-like text — biased to HCL identifiers but allows the
# adversarial slop (underscores, digits, mixed case) the fuzzer needs.
_idents = st.text(
    alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"),
    min_size=1, max_size=20,
).filter(lambda s: not s[0].isdigit())

# Random ASCII bodies — controlled length so deadlines hold.
_bodies = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126),
    min_size=0, max_size=400,
)


# ---------------------------------------------------------------------------
# _hcl_object_to_json
# ---------------------------------------------------------------------------


class TestHclObjectToJson:
    @given(_bodies)
    def test_never_raises(self, text: str) -> None:
        # The contract: on any input, returns either a dict or None —
        # never raises. Callers fall back gracefully.
        result = detect._hcl_object_to_json(text)
        assert result is None or isinstance(result, dict)

    @given(st.text(min_size=0, max_size=10))
    def test_short_garbage_returns_none(self, text: str) -> None:
        # Anything that doesn't start with `{` is guaranteed-None.
        if not text.strip().startswith("{"):
            assert detect._hcl_object_to_json(text) is None

    @given(_idents, st.text(alphabet="abcdefghij0123456789", min_size=1, max_size=20))
    def test_simple_kv_round_trips(self, key: str, value: str) -> None:
        # `{ key = "value" }` should round-trip to `{key: value}`.
        text = '{ ' + key + ' = "' + value + '" }'
        result = detect._hcl_object_to_json(text)
        # Either parses (and matches) or returns None — never partial.
        if result is not None:
            assert result == {key: value}


# ---------------------------------------------------------------------------
# block_arg_value
# ---------------------------------------------------------------------------


class TestBlockArgValue:
    @given(_bodies, _idents)
    def test_never_raises(self, body: str, arg: str) -> None:
        # Contract: returns Optional[str] for any input. Never raises.
        result = detect.block_arg_value(body, arg)
        assert result is None or isinstance(result, str)

    @given(_idents, st.text(alphabet="abcdefghij_0123456789-", min_size=1, max_size=30))
    def test_quoted_value_strips_quotes(self, arg: str, value: str) -> None:
        # Round-3 audit fix #8 — assert the contract unconditionally.
        # Previously: `if result is not None: assert result == value`
        # which passed even if the function always returned None (the
        # property test became a tautology). The contract is "a
        # well-formed `arg = "value"` line returns `value`"; that
        # contract must hold for every input the strategy produces.
        body = f'  {arg} = "{value}"'
        result = detect.block_arg_value(body, arg)
        assert result == value, (
            f"block_arg_value({body!r}, {arg!r}) returned {result!r}; "
            f"expected {value!r}"
        )

    @given(_idents)
    def test_missing_arg_returns_none(self, arg: str) -> None:
        # An arg that never appears in the body returns None.
        body = "  unrelated = 1"
        # Skip the lucky collision case where arg == 'unrelated'.
        if arg != "unrelated":
            assert detect.block_arg_value(body, arg) is None

    @given(_bodies)
    def test_arbitrary_arg_lookup_doesnt_crash(self, body: str) -> None:
        # Pick a few common-looking argument names and assert no crash.
        for arg in ("encrypted", "name", "enabled", "x"):
            detect.block_arg_value(body, arg)

    def test_escaped_quotes_dont_break_quote_state(self) -> None:
        """Audit follow-up #6 — `\\"` inside a quoted value must not
        toggle the in-quote flag. Previously the quote-state walker
        treated every `"` byte as a state-changer, so a value containing
        an escaped quote would prematurely exit the quoted region and
        downstream parsing returned a corrupted slice.
        """
        # The HCL primitive returns the inner literal with the outer
        # quotes stripped. The escape-aware walker should treat the
        # inner `\"` pair as part of the value, not as a quote pair.
        body = 'arg = "foo \\"bar\\" baz"'
        result = detect.block_arg_value(body, "arg")
        assert result == 'foo \\"bar\\" baz', f"got {result!r}"

    def test_hash_inside_escaped_quoted_value_not_treated_as_comment(self) -> None:
        """Audit follow-up #6 — `#` inside a quoted region is data, not
        a comment. The bug surfaces when a `\\"` flips us out of dq
        prematurely and a later `#` is read as comment-start.
        """
        body = 'arg = "value with \\"#hash\\" inside"'
        result = detect.block_arg_value(body, "arg")
        assert result == 'value with \\"#hash\\" inside', f"got {result!r}"


# ---------------------------------------------------------------------------
# _resolve_var_ref
# ---------------------------------------------------------------------------


class TestResolveVarRef:
    @given(_bodies)
    def test_never_raises_on_arbitrary_input(self, val: str) -> None:
        result = detect._resolve_var_ref(val, {})
        assert isinstance(result, str)

    @given(_bodies)
    def test_idempotent_when_no_vars_known(self, val: str) -> None:
        # With an empty defaults dict, plain non-reference values pass
        # through unchanged. (References to unknown vars also pass through.)
        result = detect._resolve_var_ref(val, {})
        assert isinstance(result, str)
        # Strict idempotence: applying twice yields the same answer.
        assert detect._resolve_var_ref(result, {}) == result

    @given(_idents,
           st.text(alphabet="abcdefghij0123456789", min_size=1, max_size=20))
    def test_known_var_substituted(self, var_name: str, value: str) -> None:
        # `var.foo` with var_defaults["foo"] = "bar" → "bar".
        ref = f"var.{var_name}"
        result = detect._resolve_var_ref(ref, {var_name: value})
        assert result == value


# ---------------------------------------------------------------------------
# _expand_dynamic_blocks
# ---------------------------------------------------------------------------


class TestExpandDynamicBlocks:
    @given(_bodies)
    def test_never_raises_on_arbitrary_input(self, body: str) -> None:
        result = detect._expand_dynamic_blocks(body)
        assert isinstance(result, str)

    @given(_bodies)
    def test_no_dynamic_markers_left_in_output_for_fully_balanced_input(
        self, body: str,
    ) -> None:
        # If the input was fully expanded (return path B in the
        # function), the output won't contain `dynamic "` headers
        # for inputs that weren't truncated. We can't promise
        # complete elimination on truncated input — so this test
        # is intentionally a smoke check of "doesn't add dynamic
        # markers." The starting count is the upper bound on the
        # ending count.
        before = body.count('dynamic "')
        result = detect._expand_dynamic_blocks(body)
        after = result.count('dynamic "')
        assert after <= before

    def test_simple_dynamic_block_flattened(self) -> None:
        body = '''
        dynamic "ingress" {
          for_each = var.rules
          content {
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        '''
        result = detect._expand_dynamic_blocks(body)
        assert 'dynamic "' not in result
        assert "ingress" in result
        assert "cidr_blocks" in result


# ---------------------------------------------------------------------------
# find_blocks — the top-level block locator
# ---------------------------------------------------------------------------


class TestFindBlocks:
    @given(_bodies)
    def test_never_raises_on_arbitrary_input(self, text: str) -> None:
        # `find_blocks` is invoked once per regex per file; a crash
        # here wedges the LSP for the whole workspace.
        result = detect.find_blocks(text, detect.RESOURCE_START)
        assert isinstance(result, list)
        for blk in result:
            assert "start_line" in blk
            assert "block_text" in blk

    @given(_bodies)
    def test_unbalanced_braces_dont_raise(self, text: str) -> None:
        # Inject deliberately-unbalanced braces. The function must still
        # return a list — possibly empty for truncated input.
        evil = text + ('{' * 10)
        result = detect.find_blocks(evil, detect.RESOURCE_START)
        assert isinstance(result, list)

    def test_empty_string_is_safe(self) -> None:
        assert detect.find_blocks("", detect.RESOURCE_START) == []

    def test_well_formed_resource_block_is_found(self) -> None:
        text = (
            'resource "aws_s3_bucket" "my_bucket" {\n'
            '  bucket = "my-bucket"\n'
            '}\n'
        )
        result = detect.find_blocks(text, detect.RESOURCE_START)
        assert len(result) == 1
        assert result[0]["groups"] == ("aws_s3_bucket", "my_bucket")


# ---------------------------------------------------------------------------
# brace_walk — shared depth tracker (Round 30.13)
# ---------------------------------------------------------------------------


class TestBraceWalk:
    """Round 30.13 — single quote-aware brace/paren depth walker.

    Replaces 21+ duplicated depth-tracking loops across `detect.py` and
    `_apply_fixes.py`. The class-level docstring of `brace_walk` in
    `_hcl.py` documents the contract; these tests pin the edge cases.
    """

    def _bw(self, *args, **kwargs):
        # Helper so the tests don't have to remember the import.
        from _hcl import brace_walk  # type: ignore
        return brace_walk(*args, **kwargs)

    def test_balanced_top_level(self) -> None:
        text = "{ a }"
        # Walks from 0, consumes opening { at 0, matches } at 4, returns 5.
        assert self._bw(text, 0) == 5

    def test_nested_braces(self) -> None:
        text = "{ a { b } c }"
        assert self._bw(text, 0) == len(text)

    def test_unbalanced_returns_none(self) -> None:
        assert self._bw("{ a { b }", 0) is None
        assert self._bw("{", 0) is None
        assert self._bw("", 0) is None

    def test_quoted_close_brace_is_ignored(self) -> None:
        # `}` inside a quoted string MUST NOT decrement depth.
        # Without quote awareness this would return early at the } in
        # the string and corrupt the extracted block.
        text = '{ name = "arn:aws:s3:::bucket-{*}-policy" }'
        # The walker must reach the trailing } at len-1.
        assert self._bw(text, 0) == len(text)

    def test_quoted_open_brace_is_ignored(self) -> None:
        # Same in the opposite direction — `{` inside a string MUST NOT
        # increment depth.
        text = '{ name = "value with { in it" }'
        assert self._bw(text, 0) == len(text)

    def test_escaped_quote_does_not_toggle_quote_state(self) -> None:
        # `\\"` inside a quoted region keeps us in-quote; a literal }
        # inside such a region must still be ignored.
        text = '{ key = "foo \\"bar}baz\\" qux" }'
        assert self._bw(text, 0) == len(text)

    def test_single_quoted_string_handled(self) -> None:
        # HCL accepts single quotes only inside heredocs / interpolation,
        # but the walker tracks them defensively so a passing test
        # input that uses `'…'` doesn't false-balance.
        text = "{ k = 'v with } inside' }"
        assert self._bw(text, 0) == len(text)

    def test_paren_walker_via_opens_closes_kwargs(self) -> None:
        # The same logic must work for parentheses — `jsonencode(...)`
        # extraction needs paren-depth, not brace-depth.
        text = 'jsonencode({ "foo": "bar" }) tail'
        start = text.index("(")
        end = self._bw(text, start, opens="(", closes=")")
        # End is one past the closing paren, before the space.
        assert end is not None
        assert text[end - 1] == ")"
        assert text[end:].startswith(" tail")

    def test_start_pos_skips_leading_garbage(self) -> None:
        # Caller decides where to start; brackets before start_pos are
        # ignored.
        text = "leading { content }"
        start = text.index("{")
        assert self._bw(text, start) == len(text)

    def test_returns_position_one_past_close(self) -> None:
        # Caller convention: end_pos is exclusive (slice-friendly).
        text = "{a}{b}"
        end = self._bw(text, 0)
        assert end == 3
        # Slicing with the returned position gives the matched span.
        assert text[0:end] == "{a}"

    def test_does_not_raise_on_arbitrary_input(self) -> None:
        # Brittleness guard — same shape as the find_blocks property
        # test above. Unbalanced + truncated + binary garbage all
        # return None or a valid offset, never raise.
        for evil in ["", "{", "}", "{{{{", "}}}}", '{ "unterm', "\x00"]:
            try:
                result = self._bw(evil, 0)
            except Exception as e:
                raise AssertionError(f"brace_walk raised on {evil!r}: {e}")
            assert result is None or isinstance(result, int)
