"""HCL primitives — fourth seam in the detect.py modularisation.

This module groups the *pure* HCL helpers from `detect.py`: text
normalisation, comment scrubbing, top-level block extraction, attribute
presence checks, JSON-from-HCL coercion, nested-path lookup, and the
`dynamic "X" { content { ... } }` rewrite pre-pass.

Scope rule — same as `_versions.py` and `_scoring.py`:

  * Pure functions and immutable regex constants only.
  * Zero engine state. Anything that reads the `_USE_HCL2` toggle, the
    var-resolution layer, or the catalogue stays in `detect.py` for now.

That rule is what made the seam shippable: every helper here can be
reasoned about in isolation, and the test surface is already locked
by `tests/test_hcl_primitives.py` (which reaches them via the
`detect` module's re-export shim).

Why this seam pays off:

  * Every other extract that touches resource bodies depends on these
    primitives. Pulling them out first gives later sessions
    (`_var_resolve.py`, `_attack_graph.py`, `_catalog.py`) a clean
    import to depend on instead of poking back into `detect.py`.
  * `find_blocks` is the inner loop of every per-resource scan.
    Centralising it removes the temptation to inline a fifth or sixth
    brace-balancer across the codebase.

Public surface
--------------

Constants
~~~~~~~~~

* ``_LINE_COMMENT_RE``, ``_BLOCK_COMMENT_RE`` — used by
  ``strip_hcl_context``. Exported so detect.py's existing module-level
  references stay binding-equal after the move.
* ``_DYNAMIC_BLOCK_START_RE`` — used by ``_expand_dynamic_blocks``.

Functions
~~~~~~~~~

* ``_read_normalized(path)`` — read text, normalise CRLF/CR to LF.
* ``_parse_scalar(v)`` — coerce a YAML-ish bareword to a Python scalar.
* ``strip_hcl_context(text)`` — replace HCL comments with whitespace,
  preserving line numbers.
* ``find_blocks(text, regex)`` — locate top-level HCL blocks by
  brace-balanced extraction; returns dicts with start/end positions,
  body, and the regex match for header introspection.
* ``find_simple_blocks(text, regex)`` — same, but for header regexes
  with no capture groups (e.g. ``moved``, ``import``).
* ``block_has_arg(body, arg)`` — top-level argument presence
  (assignment OR nested block opener).
* ``_hcl_object_to_json(text)`` — best-effort coerce an HCL object
  literal (as found inside ``jsonencode(...)``) to a Python dict.
* ``block_has_nested_path(body, path)`` — recursive nested-path
  presence check, e.g. ``settings.backup_configuration.enabled``.
* ``_expand_dynamic_blocks(body)`` — replace
  ``dynamic "X" { content { ... } }`` with ``X { ... }`` so
  attribute-presence patterns can match inside dynamic blocks.

Names are intentionally preserved; ``detect.py`` re-imports them all
under their original (often single-underscore-prefixed) identifiers so
existing call sites and tests need no migration.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path


# ---- Optional python-hcl2 fast-path -------------------------------------
#
# The skill's default contract is stdlib-only — no pip install required to
# run a scan. python-hcl2 (when installed) provides heredoc-aware
# attribute extraction that the regex path can't match. Off by default,
# enabled per-run via `--use-hcl2` or `TF_ANALYZE_USE_HCL2=1`.
#
# Lives here (rather than in detect.py) as of Session F so that callers
# from other seamed modules (`_cross_resource.py`) can reach
# `block_arg_value` without circular imports back into detect.
try:
    import hcl2 as _hcl2  # type: ignore
    _HAS_HCL2 = True
except Exception:
    _hcl2 = None  # type: ignore
    _HAS_HCL2 = False

_USE_HCL2 = False  # toggled by main() in detect.py after argparse


def _enable_hcl2_or_warn() -> None:
    """[legacy] Old explicit-opt-in path. Kept as a thin wrapper around
    `_enable_hcl2_default()` so any caller using --use-hcl2 still works.
    """
    _enable_hcl2_default()


def _enable_hcl2_default() -> None:
    """Enable the python-hcl2 fast-path. Silent no-op when the dependency
    isn't present — the caller already decided whether to print a notice."""
    global _USE_HCL2
    if _HAS_HCL2:
        _USE_HCL2 = True


def _hcl2_block_arg_value(body: str, arg: str) -> str | None:
    """Heredoc-aware attribute extraction. Wraps the body in a synthetic
    block so hcl2 will parse it, then walks the parse tree for `arg`.
    Returns None on any error so callers fall back to the regex path.
    """
    if not (_USE_HCL2 and _HAS_HCL2):
        return None
    try:
        # hcl2.load expects a top-level construct; wrap the bare body.
        wrapped = f'_arg_extract {{\n{body}\n}}'
        parsed = _hcl2.load(io.StringIO(wrapped))
    except Exception:
        return None
    try:
        block_list = parsed.get("_arg_extract", [])
        if not isinstance(block_list, list) or not block_list:
            return None
        block = block_list[0] if isinstance(block_list[0], dict) else None
        if not block:
            return None
        val = block.get(arg)
    except Exception:
        return None
    if val is None:
        return None
    if isinstance(val, list) and val:
        val = val[0]
    if isinstance(val, str):
        # hcl2 strips heredoc markers; return the literal content.
        return val
    return str(val)


# ---- Text normalisation -------------------------------------------------

def _read_normalized(path: Path) -> str:
    """Read a text file and normalize line endings to LF.

    Without normalization, `text.count('\\n', 0, pos)` undercounts on CRLF
    files: every `\\r\\n` becomes one `\\n` after normalization, and the
    `\\r` carried position offset from the disk byte stream made line
    numbers in findings drift on Windows-edited code. The fix is cheap
    and the substring searches are unaffected.
    """
    return path.read_text().replace("\r\n", "\n").replace("\r", "\n")


def _parse_scalar(v: str):
    if v == "":
        return None
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v


# ---- HCL comment/string scrubbing ---------------------------------------
# Used by grep-kind patterns that set `hcl_context: true` — we don't want
# `# ignore_changes = all` in a docstring to fire ROB-DRIFT-001. Line
# numbers are preserved so downstream (file, line, id) stays accurate.

_LINE_COMMENT_RE = re.compile(r'(?m)(^|[^"\'])(#|//)[^\n]*')
_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)


def strip_hcl_context(text: str) -> str:
    """Replace comments with equal-length whitespace so byte offsets AND
    line numbers of remaining code match the original. String literals
    are left alone — patterns that would false-positive on strings
    should be HCL-aware (resource_arg, hcl_attr) rather than grep.

    Contract pinned by ``test_strip_hcl_context_preserves_length_and_offsets``
    in ``tests/test_audit_2026_05_11_regressions.py`` (round-3 audit).
    Length-preserving alone wasn't enough: a multi-line ``/* ... */``
    comment used to have its newlines replaced with spaces, which
    shifted every line count after it. The block-comment substitution
    now preserves newline positions explicitly.
    """
    def blank(match: re.Match) -> str:
        s = match.group(0)
        # Preserve the first captured char if it's not part of the comment.
        lead = match.group(1) if match.lastindex else ""
        # Round-3 audit fix — keep newlines (line-comments don't match
        # them, but a defensive replace here costs nothing).
        rest = "".join(c if c == "\n" else " " for c in s[len(lead):])
        return lead + rest
    out = _LINE_COMMENT_RE.sub(blank, text)
    # Round-3 audit fix — block comments span multiple lines, so
    # replacing the whole match with N spaces previously converted
    # internal newlines to spaces and shifted line counts in code
    # following a /* ... */ comment.
    out = _BLOCK_COMMENT_RE.sub(
        lambda m: "".join(c if c == "\n" else " " for c in m.group(0)),
        out,
    )
    return out


# ---- Quote-aware depth walker ------------------------------------------
#
# Round 30.13 structural fix — every prior audit recommended pulling
# this helper out so the 12+ duplicated brace-tracking loops in
# `detect_in_file` (plus the 2 in `_apply_fixes`) share one
# implementation. The existing `find_blocks` / `find_simple_blocks`
# walkers above don't track quotes — they work on top-level HCL scopes
# where `}` inside a string is rare in practice. The inline detector
# branches DO see quoted braces (IAM policy ARNs like
# ``arn:aws:s3:::bucket-{*}-policy``, Helm `set` map values with
# brace-bearing strings, heredoc bodies) so they need a quote-aware
# walker.
#
# The helper is parameterised on `opens` / `closes` so the same logic
# powers paren-depth tracking (`jsonencode(...)` extraction in the
# `iam_json_policy_analysis` detector) too.


def brace_walk(
    text: str,
    start_pos: int = 0,
    *,
    opens: str = "{",
    closes: str = "}",
) -> int | None:
    """Walk ``text`` from ``start_pos``, tracking quote-aware bracket depth.

    Returns the position **immediately after** the closing bracket that
    matches the first opening bracket encountered — i.e. the position
    where the cumulative depth returns to 0. Returns ``None`` on
    unbalanced input.

    Quote state is tracked with backslash awareness:

    * Double quotes (``"``) and single quotes (``'``) each toggle their
      own state flag.
    * A backslash immediately before a quote (``\\"``) prevents the
      toggle, so a value like ``key = "with \\"quoted\\" inside"`` is
      treated as a single string literal.
    * Brackets inside any active string literal do **not** affect depth.

    Customise ``opens`` / ``closes`` to walk other balanced delimiters:

        >>> brace_walk('foo(bar(baz)quux)tail', text.index('('), opens='(', closes=')')
        17

    Notes:

    * Heredoc bodies (``<<-EOF ... EOF``) are NOT specially handled here.
      Callers that need heredoc-aware extraction should use
      ``block_arg_value`` (which delegates to the hcl2 parser when
      available) instead of building on this walker. In practice the
      detector branches don't encounter raw heredoc text — the regex
      pattern that triggers each branch matches HCL keywords
      (``statement``, ``set``, etc.) that don't appear inside heredoc
      content.
    * The walker is linear in the length of the text walked; no
      look-ahead.

    Args:
        text: The text to walk. The caller passes whatever they've
            already extracted (typically a block body or the text from
            a regex match start).
        start_pos: Index to start walking from. Default 0.
        opens: Opening bracket character. Default ``"{"``.
        closes: Closing bracket character. Default ``"}"``.

    Returns:
        The index one past the matching closing bracket, or ``None`` if
        the input ran out before depth returned to 0.
    """
    depth = 0
    in_dq = False
    in_sq = False
    seen_open = False
    prev = ""
    for i in range(start_pos, len(text)):
        ch = text[i]
        # `\\<char>` neutralises the next character's quote-toggling
        # effect. Tracking only the immediate prior byte is sufficient
        # for HCL: there's no `\\\\\\\"` ambiguity because a literal
        # backslash is `\\\\` and the backslash run is consumed
        # left-to-right by this same flag.
        escaped = prev == "\\"
        if ch == '"' and not in_sq and not escaped:
            in_dq = not in_dq
        elif ch == "'" and not in_dq and not escaped:
            in_sq = not in_sq
        elif not in_dq and not in_sq:
            if ch == opens:
                depth += 1
                seen_open = True
            elif ch == closes:
                depth -= 1
                if seen_open and depth == 0:
                    return i + 1
        prev = ch
    return None


# ---- Block extraction ---------------------------------------------------

def find_blocks(text: str, regex: re.Pattern) -> list[dict]:
    """Find top-level blocks. Returns list of {start_line,end_line,body,header}."""
    blocks = []
    for m in regex.finditer(text):
        start_pos = m.start()
        depth = 0
        i = m.end() - 1  # position of the opening `{`
        end_pos = None
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break
            i += 1
        if end_pos is None:
            continue
        block_text = text[start_pos:end_pos]
        body = text[m.end() : end_pos - 1]
        start_line = text.count("\n", 0, start_pos) + 1
        blocks.append(
            {
                "groups": m.groups(),
                "start_line": start_line,
                "header_match": m,
                "body": body,
                "block_text": block_text,
                "start_pos": start_pos,
                "end_pos": end_pos,
            }
        )
    return blocks


def find_simple_blocks(text: str, regex: re.Pattern) -> list[dict]:
    """Find top-level blocks for patterns without named groups (moved, import)."""
    blocks = []
    for m in regex.finditer(text):
        start_pos = m.start()
        depth = 0
        i = m.end() - 1
        end_pos = None
        while i < len(text):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end_pos = i + 1
                    break
            i += 1
        if end_pos is None:
            continue
        body = text[m.end() : end_pos - 1]
        start_line = text.count("\n", 0, start_pos) + 1
        blocks.append({"start_line": start_line, "body": body})
    return blocks


def block_has_arg(body: str, arg: str) -> bool:
    """Check if a block body has a top-level argument named `arg`.

    Matches both attribute assignments (`arg = value`) and nested block
    declarations (`arg {`), since some arguments appear as blocks in HCL.
    """
    pat = re.compile(rf'(?m)^\s*{re.escape(arg)}\s*[={{]', re.MULTILINE)
    return bool(pat.search(body))


def _hcl_object_to_json(text: str) -> dict | None:
    """Best-effort convert an HCL object literal (used inside ``jsonencode(...)``)
    to a Python dict.

    HCL accepts JSON-like object literals but with `=` instead of `:` and
    bareword keys. We do a small, conservative rewrite to canonical JSON,
    then ``json.loads`` it. Returns None on any parse failure — callers
    fall back gracefully rather than raising.
    """
    if not text or not text.strip().startswith("{"):
        return None
    s = text
    # `key = value` → `"key": value` (only when key is a bareword)
    s = re.sub(r'(?m)([{,]\s*)([A-Za-z_][\w]*)\s*=\s*', r'\1"\2": ', s)
    # Top-level (no leading delimiter) bareword `key = `
    s = re.sub(r'^\s*([A-Za-z_][\w]*)\s*=\s*', r'"\1": ', s)
    # Strip trailing commas before `}` or `]` (HCL allows them, JSON doesn't).
    s = re.sub(r',(\s*[}\]])', r'\1', s)
    # HCL list trailing commas after multi-line items
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None


def block_arg_value(body: str, arg: str) -> str | None:
    """Return the literal value of a top-level argument, stripped of quotes/comments.

    Heredoc-bearing values (`arg = <<-EOF\\n...\\nEOF`) are not handled by the
    regex path — the trailing `<<-EOF` is returned verbatim, which is rarely
    useful. When the optional hcl2 fast-path is enabled
    (`--use-hcl2` or `TF_ANALYZE_USE_HCL2=1`), heredoc bodies are extracted
    structurally so callers see the actual string value.

    Moved from detect.py into `_hcl.py` in Session F so that
    `_cross_resource.py` can call this without a circular import back
    into detect.
    """
    if _USE_HCL2 and "<<" in body:
        v = _hcl2_block_arg_value(body, arg)
        if v is not None:
            return v
    m = re.search(rf'(?m)^\s*{re.escape(arg)}\s*=\s*(.+?)\s*$', body)
    if not m:
        return None
    val = m.group(1).strip()
    if '"' in val or "'" in val:
        # Audit follow-up #6 — the quote-state walker must skip an
        # escaped quote (`\"`, `\'`) instead of toggling the in-quote
        # flag on it. Without the `prev != "\\"` guard, a value like
        # `key = "foo \"bar\""` flips out of DQ on the first `\"` and
        # the comment-strip pass eats real bytes. Tracking the prior
        # character is sufficient (HCL doesn't allow `\\\"` ambiguity
        # in scalar string syntax — a literal backslash is `\\`).
        in_dq = in_sq = False
        cut = None
        prev = ""
        for idx, ch in enumerate(val):
            escaped = prev == "\\"
            if ch == '"' and not in_sq and not escaped:
                in_dq = not in_dq
            elif ch == "'" and not in_dq and not escaped:
                in_sq = not in_sq
            elif ch == "#" and not in_dq and not in_sq:
                cut = idx
                break
            prev = ch
        if cut is not None:
            val = val[:cut].rstrip()
    else:
        cut = val.find("#")
        if cut >= 0:
            val = val[:cut].rstrip()
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    return val


def block_has_nested_path(body: str, path: str) -> bool:
    """Check if a nested HCL path like `settings.backup_configuration.enabled` is set."""
    parts = path.split(".")
    if len(parts) == 1:
        return block_has_arg(body, parts[0])
    head, tail = parts[0], parts[1:]
    nested_re = re.compile(rf'(?m)^\s*{re.escape(head)}\s*\{{')
    for m in nested_re.finditer(body):
        depth = 0
        i = m.end() - 1
        end = None
        while i < len(body):
            c = body[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if end is None:
            continue
        inner = body[m.end():end]
        if block_has_nested_path(inner, ".".join(tail)):
            return True
    return False


# ---- Dynamic block expansion --------------------------------------------

_DYNAMIC_BLOCK_START_RE = re.compile(r'dynamic\s+"([\w-]+)"\s*\{')


def _expand_dynamic_blocks(body: str) -> str:
    """Replace dynamic "X" { for_each = ... content { ... } } with X { ... }.

    This is a best-effort structural pre-pass so that resource_arg /
    resource_missing_arg / hcl_attr patterns can match attributes inside
    dynamically-generated nested blocks (e.g. dynamic "ingress" in a
    security group). Runtime values (the for_each iterable) are not
    evaluated — the goal is to surface attribute-presence checks, not to
    enumerate instances.

    Line numbers are NOT altered: the transformed body is only used for
    attribute inspection within an already-located resource block; the
    finding's reported line is always the resource block's start_line.
    """
    result: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        m = _DYNAMIC_BLOCK_START_RE.search(body, i)
        if not m:
            result.append(body[i:])
            break
        result.append(body[i:m.start()])
        block_name = m.group(1)
        # Find the outer dynamic block boundary
        depth, j, outer_end = 0, m.end() - 1, None
        while j < n:
            c = body[j]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    outer_end = j
                    break
            j += 1
        if outer_end is None:
            result.append(body[m.start():])
            break
        outer_body = body[m.end():outer_end]
        # Extract the content { ... } block inside the dynamic block
        content_m = re.search(r'(?m)^\s*content\s*\{', outer_body)
        if content_m:
            depth2, k, content_end = 0, content_m.end() - 1, None
            while k < len(outer_body):
                c = outer_body[k]
                if c == '{':
                    depth2 += 1
                elif c == '}':
                    depth2 -= 1
                    if depth2 == 0:
                        content_end = k
                        break
                k += 1
            if content_end is not None:
                content_body = outer_body[content_m.end():content_end]
                result.append(f'{block_name} {{{content_body}}}')
            else:
                result.append(body[m.start():outer_end + 1])
        else:
            result.append(body[m.start():outer_end + 1])
        i = outer_end + 1
    return ''.join(result)
