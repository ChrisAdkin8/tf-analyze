"""HCL primitives — fourth seam in the detect.py modularisation.

This module groups the *pure* HCL helpers from `detect.py`: text
normalisation, comment scrubbing, top-level block extraction, attribute
presence checks, JSON-from-HCL coercion, nested-path lookup, and the
`dynamic "X" { content { ... } }` rewrite pre-pass.

Scope rule — same as `_versions.py` and `_scoring.py`:

  * Pure functions and immutable regex constants only.
  * Zero engine state. Anything that reads the var-resolution layer or
    the catalogue stays in `detect.py` for now. (Loading the vendored
    python-hcl2 and choosing its grammar-cache path is one-time import
    setup, not engine state.)

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

import bisect
import functools
import io
import json
import os
import re
import sys
from pathlib import Path


# ---- python-hcl2 (vendored) ---------------------------------------------
#
# The engine always parses with the python-hcl2 + lark copies vendored in
# `_vendor/` (refreshed only by `scripts/vendor_deps.py`), so every surface
# runs the same parser version with no `pip install`. The vendored
# directory goes first on `sys.path`, so it wins over any installed hcl2.
# This lives in `_hcl.py` rather than `detect.py` because several entry
# points (tests, `self_test.py`, `gen_rule_docs.py`) import `_hcl` without
# `detect`. See tasks/hcl-parser-migration.md §4.1–4.2.

def _vendor_dir() -> Path | None:
    """`_vendor/` next to this file (source checkout, Docker, .vsix), or
    the `tf_analyze_vendor` package-data dir (pip-installed wheel)."""
    here = Path(__file__).resolve().parent / "_vendor"
    if (here / "hcl2").is_dir():
        return here
    try:
        import tf_analyze_vendor  # type: ignore
    except ImportError:
        return None
    return Path(tf_analyze_vendor.__file__).resolve().parent


_VENDOR_DIR = _vendor_dir()
if _VENDOR_DIR is not None and str(_VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(_VENDOR_DIR))

try:
    import hcl2 as _hcl2  # type: ignore
    import hcl2.parser as _hcl2_parser  # type: ignore
    import lark as _lark  # type: ignore
except ImportError as e:  # pragma: no cover - broken install only
    raise ImportError(
        "tf-analyze: the vendored HCL parser is missing (expected "
        f"{Path(__file__).resolve().parent / '_vendor'}). Copy the whole "
        "scripts/ directory, including _vendor/, not just the .py files."
    ) from e

HCL2_VERSION: str = _hcl2.__version__
LARK_VERSION: str = _lark.__version__
HCL2_PATH: Path = Path(_hcl2.__file__).resolve().parent


def _user_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches"
    local = os.environ.get("LOCALAPPDATA")
    if os.name == "nt" and local:
        return Path(local)
    return Path.home() / ".cache"


def _grammar_cache_path() -> Path:
    """Where lark should cache the built HCL grammar.

    Building the grammar takes ~0.35s, longer than a small scan, so it is
    cached. Order: next to the vendored `parser.py` (pre-built in the
    .vsix and Docker images; written on first use in a checkout, where it
    is gitignored); else a per-user cache dir; else os.devnull, which
    makes lark rebuild in memory every run (it tolerates an unreadable or
    unwritable cache). Never a shared directory such as /tmp: lark loads
    the cache with pickle.
    """
    default = Path(_hcl2_parser.PARSER_FILE)
    if default.exists() or os.access(default.parent, os.W_OK):
        return default
    try:
        d = _user_cache_dir() / "tf-analyze"
        d.mkdir(parents=True, exist_ok=True)
        if os.access(d, os.W_OK):
            return d / f"hcl2-{HCL2_VERSION}-lark-{LARK_VERSION}.lark_cache.bin"
    except OSError:
        pass
    return Path(os.devnull)


_hcl2_parser.PARSER_FILE = _grammar_cache_path()


def warm_grammar_cache() -> str:
    """Build (or load) the grammar once so the cache file exists. Used by
    `scripts/vendor_deps.py --warm-cache` in image / bundle builds.
    Returns the cache path."""
    _hcl2.loads("")
    return str(_hcl2_parser.PARSER_FILE)


def _hcl2_block_arg_value(body: str, arg: str) -> str | None:
    """Heredoc-aware attribute extraction. Wraps the body in a synthetic
    block so hcl2 will parse it, then walks the parse tree for `arg`.
    Returns None on any error so callers fall back to the regex path.
    """
    try:
        # hcl2.load expects a top-level construct; wrap the bare body.
        wrapped = f'_arg_extract {{\n{body}\n}}'
        parsed = _hcl2.load(io.StringIO(wrapped), with_meta=True)
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
    if val is None or _is_block_list(val):
        # Absent, or a nested block rather than a value (the regex path
        # only ever matches `arg =`, so it agrees).
        return None
    # Render like the regex path: strings unquoted (heredoc markers are
    # already stripped by hcl2), lists / maps as HCL text. This used to
    # return `val[0]` for a list — a leftover from old python-hcl2, which
    # wrapped every value in a list — so in any body containing a heredoc
    # only the first element of e.g. `actions = ["s3:GetObject", "*"]`
    # was seen.
    return render_hcl(val)


# ---- Parse tree (python-hcl2) -------------------------------------------
#
# Step 2 of tasks/hcl-parser-migration.md: each `.tf` file is parsed once
# per process and the tree is shared by every caller. Memoised on the text
# itself rather than threading a per-run map through every consumer — the
# effect is the same (one parse per distinct file), it needs no plumbing,
# and long-lived callers (LSP, trend, fleet) re-parse only text that
# actually changed.

# Test-only switch: treat every file as unparseable so the whole suite can
# be run through the regex fallback (tasks/hcl-parser-migration.md §4.7).
_FORCE_FALLBACK_ENV = "TF_ANALYZE_TEST_FORCE_FALLBACK"


@functools.lru_cache(maxsize=1024)
def _parse_tf_cached(text: str) -> tuple[dict | None, str | None]:
    try:
        return _hcl2.loads(text.lstrip("﻿"), with_meta=True), None
    except Exception as e:  # lark raises a family of exception types
        first = str(e).strip().splitlines()[0] if str(e).strip() else ""
        error = f"{type(e).__name__}: {first}"[:200]
    # python-hcl2's grammar rejects a conditional whose `?` / `:` starts a
    # new line inside parentheses — valid HCL, and one such local sent the
    # whole file to the regex fallback (losing a SEC-AWS-SG-001 finding
    # elsewhere in it). Retry once with those continuations joined.
    joined = _join_conditional_continuations(text)
    if joined != text:
        try:
            return _hcl2.loads(joined.lstrip("﻿"), with_meta=True), None
        except Exception:
            pass
    return None, error


def _join_conditional_continuations(text: str) -> str:
    """`text` with each line break that precedes a `?` / `:` inside
    parentheses replaced by a space. The removed breaks are re-added at
    the end of the line holding the closing `)`, so every later line keeps
    its number (block line metadata stays right)."""
    stripped = mask_comments_and_heredocs(text)
    code = list(stripped)
    i = 0
    while (i := stripped.find('"', i)) != -1:  # blank string contents
        end = _string_end(text, i)
        for k in range(i + 1, max(i + 1, end - 1)):
            if code[k] != "\n":
                code[k] = " "
        i = max(end, i + 1)
    masked = "".join(code)
    out = list(text)
    pos = 0
    for m in re.finditer(r"\(", masked):
        if m.start() < pos:
            continue
        close = brace_walk(text, m.start(), opens="(", closes=")")
        if close is None:
            continue
        breaks = [b.start() for b in re.finditer(r"\n(?=[ \t]*[?:](?!:))", masked[m.start():close])]
        if breaks:
            for b in breaks:
                out[m.start() + b] = " "
            eol = text.find("\n", close)
            eol = len(text) if eol < 0 else eol
            out[eol - 1] = out[eol - 1] + "\n" * len(breaks) if eol > 0 else out[eol - 1]
        pos = close
    return "".join(out)


def parse_tf(text: str) -> tuple[dict | None, str | None]:
    """Parse `.tf` text. Returns ``(tree, None)`` on success, or
    ``(None, reason)`` when python-hcl2 rejects it — callers then fall
    back to the regex model for that file. A leading UTF-8 BOM is
    ignored. Under the test-only fallback switch returns ``(None, None)``
    (no tree, but nothing to report)."""
    if os.environ.get(_FORCE_FALLBACK_ENV) == "1":
        return None, None
    return _parse_tf_cached(text)


def normalise_attrs(body: dict) -> dict:
    """Return a copy of a resource/block subtree with every
    ``dynamic "X" { content { ... } }`` folded in as a plain ``X`` block,
    recursively — the tree counterpart of `_expand_dynamic_blocks`. The
    ``for_each`` value is dropped: values that come from it
    (``${X.value}``) are unknown at parse time."""
    out: dict = {}
    dynamic = body.get("dynamic")
    for k, v in body.items():
        if k == "dynamic":
            continue
        if isinstance(v, list):
            out[k] = [normalise_attrs(i) if isinstance(i, dict) else i for i in v]
        elif isinstance(v, dict):
            out[k] = normalise_attrs(v)
        else:
            out[k] = v
    for item in dynamic or []:
        if not isinstance(item, dict):
            continue
        for name, spec in item.items():
            if not isinstance(spec, dict):
                continue
            for content in spec.get("content") or []:
                if isinstance(content, dict):
                    out.setdefault(name, [])
                    if isinstance(out[name], list):
                        out[name].append(normalise_attrs(content))
    return out


def resource_subtrees(tree: dict | None) -> dict[tuple[str, str], list[dict]]:
    """``{(type, name): [subtree, ...]}`` for every ``resource`` block in a
    parsed file. A key with more than one subtree is ambiguous (invalid
    Terraform, or resource text the regex scanner also saw twice)."""
    out: dict[tuple[str, str], list[dict]] = {}
    for item in (tree or {}).get("resource") or []:
        if not isinstance(item, dict):
            continue
        for rtype, named in item.items():
            if not isinstance(named, dict):
                continue
            for rname, body in named.items():
                if isinstance(body, dict):
                    out.setdefault((rtype, rname), []).append(body)
    return out


def attrs_has_path(attrs: dict, path: str, *, every: bool = True) -> bool:
    """Tree counterpart of `block_has_nested_path` (§4.4 rules 1–3).

    A one-segment path is a key of the block itself — never a key inside
    an object attribute or nested block. Each further segment walks into
    a nested block, a list-of-objects attribute (``ingress = [{...}]``),
    or an object attribute named by the path. When the segment is
    repeated (several blocks / list items), the rest of the path must
    hold for **every** instance — or, with ``every=False`` (a pattern's
    ``instances: any``), for at least one.
    """
    head, _, rest = path.partition(".")
    if not isinstance(attrs, dict) or head not in attrs:
        return False
    if not rest:
        return True
    value = attrs[head]
    instances = value if isinstance(value, list) else [value]
    instances = [i for i in instances if isinstance(i, dict)]
    check = all if every else any
    return bool(instances) and check(attrs_has_path(i, rest, every=every) for i in instances)


# ---- Rendering tree values (Step 3) -------------------------------------
#
# Catalogue regexes were written against HCL source text as
# `block_arg_value` returns it: strings unquoted, expressions bare,
# collections in HCL syntax with quoted strings, bools lower-case. Tree
# values are rendered back to that text so the same regexes keep matching
# (tasks/hcl-parser-migration.md §4.6).

_HCL_IDENT_RE = re.compile(r'^[A-Za-z_][\w-]*$')


def single_interpolation(value: str) -> str | None:
    """If ``value`` is exactly one ``${ ... }`` covering the whole string,
    return the expression inside it, else None.

    ``"${var.a}-${var.b}"`` (two interpolations), ``"pre-${var.x}"``
    (literal text) and ``"$${x}"`` (an escaped, literal ``${``) are not
    single interpolations. Braces and quotes inside the expression are
    tracked, so ``${{for k, v in m : k => v}}`` is one interpolation.
    """
    if not (value.startswith("${") and value.endswith("}")):
        return None
    depth = 1
    i = 2
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == '"':
            i = _string_end(value, i)
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return value[2:i] if i == n - 1 else None
        i += 1
    return None


def _render_scalar_in_collection(value) -> str:
    if isinstance(value, str):
        expr = single_interpolation(value)
        if expr is not None:
            return expr
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return render_hcl(value)


def render_hcl(value) -> str:
    """Render a python-hcl2 value as the HCL text `block_arg_value` would
    return for it: a top-level string is unquoted (and a single
    interpolation is unwrapped to its expression, ``"${var.x}"`` ->
    ``var.x``); ``true``/``false``/``null``; numbers as written; lists and
    objects in HCL syntax with double-quoted strings, e.g.
    ``["0.0.0.0/0", var.z]`` and ``{Name = "n", "k-2" = 3}``."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        expr = single_interpolation(value)
        return expr if expr is not None else value
    if isinstance(value, list):
        return "[" + ", ".join(_render_scalar_in_collection(v) for v in value) + "]"
    if isinstance(value, dict):
        items = []
        for k, v in value.items():
            if k.startswith("__") and k.endswith("__"):
                continue  # __start_line__ / __end_line__ metadata
            key = k if _HCL_IDENT_RE.match(k) else '"' + k.replace('"', '\\"') + '"'
            items.append(f"{key} = {_render_scalar_in_collection(v)}")
        return "{" + ", ".join(items) + "}"
    return str(value)


def attrs_values_at(attrs: dict, path: str) -> list:
    """Every value at ``path`` (dotted, walked like `attrs_has_path`),
    across all instances of repeated blocks, in source order. Empty when
    the path is absent anywhere. A one-segment path is a top-level key."""
    head, _, rest = path.partition(".")
    if not isinstance(attrs, dict) or head not in attrs:
        return []
    value = attrs[head]
    if not rest:
        return [value]
    instances = value if isinstance(value, list) else [value]
    out: list = []
    for inst in instances:
        if isinstance(inst, dict):
            out.extend(attrs_values_at(inst, rest))
    return out

def _is_block_list(value) -> bool:
    """A nested block in the tree: a list of dicts carrying line metadata."""
    return (
        isinstance(value, list) and bool(value)
        and all(isinstance(v, dict) and "__start_line__" in v for v in value)
    )


def _top_level_arg_value(body: str, arg: str) -> str | None:
    """Alias of `block_arg_value`, which is top-level only since parser
    migration Step 5. Kept for `_network` and older imports."""
    return block_arg_value(body, arg)


def block_values_at(body: str, path: str) -> list[str]:
    """Regex fallback for `resource_values_at`: every value at ``path``,
    walked like `block_has_nested_path` (top-level lookups; blocks and
    object attributes; all instances of a repeated segment)."""
    head, _, rest = path.partition(".")
    if not rest:
        v = _top_level_arg_value(body, head)
        return [] if v is None else [v]
    masked = _mask_to_top_level(body)
    opener = re.compile(rf'(?m)^[ \t]*{re.escape(head)}[ \t]*(?:=[ \t]*)?\{{')
    out: list[str] = []
    for m in opener.finditer(masked):
        open_pos = m.end() - 1
        close_pos = masked.find("}", open_pos + 1)
        if close_pos >= 0:
            out.extend(block_values_at(body[open_pos + 1:close_pos], rest))
    return out


def resource_values_at(blk: dict, path: str) -> list[str]:
    """Every value at ``path`` in a resource block, as HCL text (strings
    unquoted, expressions bare — what `block_arg_value` returns), across
    all instances of repeated blocks. A path that ends at a nested block
    (not a value) yields nothing. Uses the parse tree when attached, else
    the regex fallback with the same rules."""
    attrs = blk.get("attrs")
    if attrs is None:
        return block_values_at(blk["body"], path)
    return [
        render_hcl(v) for v in attrs_values_at(attrs, path)
        if not _is_block_list(v)
    ]

def resource_has_path(blk: dict, path: str, *, every: bool = True) -> bool:
    """Presence check for a resource block found by `find_blocks`: uses
    the parse tree when `detect_in_file` attached one (``blk["attrs"]``),
    else the regex fallback, which follows the same rules as far as text
    allows."""
    attrs = blk.get("attrs")
    if attrs is not None:
        return attrs_has_path(attrs, path, every=every)
    if "." in path:
        return block_has_nested_path(blk["body"], path, every=every)
    return block_has_arg(blk["body"], path)


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
    in ``tests/test_audit_2026_05_11_regressions.py`` (round-3 audit):
    length and every newline position are preserved (comment bytes become
    spaces; newlines are never touched).

    Now a single-pass, **string-aware** tokenizer. The old regex blanked a
    ``#``/``//`` even inside a string (``x = "http://foo"`` lost everything
    after ``//``) and missed a comment that immediately followed a closing
    quote (``v = "x"# c``). HCL has only double-quoted strings, so quote
    tracking is double-quote + backslash-escape only (`_string_end`), and
    heredoc bodies are skipped whole — a quote inside a `user_data`
    script used to flip the string state for the rest of the file.
    """
    out = list(text)
    n = len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "#" or (ch == "/" and nxt == "/"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif ch == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif ch == '"':
            # Escape- and `${...}`-aware: `"C:\\\\"` closes where it should.
            i = _string_end(text, i)
        elif ch == "<" and nxt == "<" and (hd := _HEREDOC_START_RE.match(text, i)):
            # Heredoc text is kept (secret scanning reads it) but skipped
            # whole, so a `"` or `#` in a script cannot flip the string /
            # comment state for the rest of the file.
            term = re.compile(rf'(?m)^[ \t]*{re.escape(hd.group(1))}[ \t]*\r?$')
            t = term.search(text, hd.end())
            i = n if t is None else t.end()
        else:
            i += 1
    return "".join(out)


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

    String and comment state is tracked so brackets that aren't real
    structure don't affect depth:

    * Double quotes (``"``) toggle string state. HCL has **no**
      single-quoted strings, so ``'`` is an ordinary character — this
      matters because apostrophes are common in comments
      (``# the child's bucket``) and must not be read as a string start.
    * ``#`` and ``//`` begin a line comment (to the next newline);
      ``/* … */`` is a block comment. Brackets, quotes and apostrophes
      inside a comment do **not** affect depth.
    * A backslash immediately before a quote (``\\"``) prevents the
      toggle, so a value like ``key = "with \\"quoted\\" inside"`` is one
      string literal.
    * Brackets inside any active string literal or comment do **not**
      affect depth.

    Customise ``opens`` / ``closes`` to walk other balanced delimiters:

        >>> brace_walk('foo(bar(baz)quux)tail', text.index('('), opens='(', closes=')')
        17

    Notes:

    * Heredoc bodies (``<<-EOF ... EOF``) are skipped whole, so a
      ``#``, quote or bracket inside a script does not affect depth.
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
    in_dq = False             # inside a "double-quoted" string
    in_line_comment = False   # after # or // until newline
    in_block_comment = False  # after /* until */
    seen_open = False
    prev = ""
    misses = _Misses()
    i = start_pos
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if prev == "*" and ch == "/":
                in_block_comment = False
                ch = ""  # consume so this `/` can't re-open a token
        elif in_dq:
            # A backslash escapes the next character, which is skipped
            # whole: checking only the previous byte left `"C:\\\\"` (an
            # escaped backslash, then the closing quote) open to the end
            # of the text.
            if ch == "\\":
                prev = ""
                i += 2
                continue
            if ch == '"':
                in_dq = False
        elif ch == '"':
            in_dq = True
        elif ch == "<" and nxt == "<" and (hd := _HEREDOC_START_RE.match(text, i)):
            # A heredoc body is opaque: a `#`, quote or bracket in a
            # script must not start a comment or move the depth.
            i = _heredoc_end(text, hd.end(), hd.group(1), misses)
            prev = ""
            continue
        elif ch == "#":
            in_line_comment = True
        elif ch == "/" and nxt == "/":
            in_line_comment = True
        elif ch == "/" and nxt == "*":
            in_block_comment = True
        elif ch == opens:
            depth += 1
            seen_open = True
        elif ch == closes:
            depth -= 1
            if seen_open and depth == 0:
                return i + 1
        prev = ch
        i += 1
    return None


# ---- Block extraction ---------------------------------------------------
#
# Block discovery is one lexer pass per file (memoised on the text), not a
# header regex per block type. The old `^\s*resource\s+"…"` scan matched
# headers inside `/* */` comments and heredocs, missed valid headers with
# unquoted labels or a comment before the labels, swallowed preceding
# blank lines into `start_line`, and re-walked to EOF for every unclosed
# header (quadratic on hostile input). The lexer knows strings (with
# `${…}` / `%{…}` templates), comments and heredocs, so none of those can
# fake or hide a block boundary.
#
# `find_blocks(text, regex)` keeps its signature: each discovered header is
# rendered in canonical form (`resource "a" "b" {`) and the caller's regex
# decides whether it is wanted and supplies `groups`.

_TOP_LEVEL_KEYWORDS = frozenset({
    "resource", "data", "module", "variable", "locals", "output",
    "provider", "terraform", "moved", "import", "removed", "check",
})

_LEX_RE = re.compile(
    r'(?P<nl>\n)'
    r'|(?P<ws>[ \t\r\f\v\ufeff]+)'
    r'|(?P<lc>(?:#|//)[^\n]*)'
    r'|(?P<bc>/\*)'
    r'|(?P<hd><<-?[ \t]*(?P<hid>[A-Za-z_][\w-]*)[ \t]*\r?\n)'
    r'|(?P<dq>")'
    r'|(?P<lb>\{)'
    r'|(?P<rb>\})'
    r'|(?P<id>[A-Za-z_][\w-]*)'
    r'|(?P<other>.)',
    re.DOTALL,
)
_STRING_STOP_RE = re.compile(r'["\\$%]')
_BLOCK_LABEL_RE = re.compile(r'^[\w-]+$')
_IDENT_LABEL_RE = re.compile(r'^[A-Za-z_][\w-]*$')


# Recovery rule: a heredoc, block comment or template that never closes
# is invalid HCL. Rather than let it swallow the rest of the file (and so
# hide every block after it), the lexer gives up on that construct and
# resumes on the next line — a broken construct costs at most its line.
#
# Cost rule: every helper is linear. A quoted string (with any `${…}` in
# it) never crosses its line — the vendored parser rejects a newline or
# comment there too — and nesting is capped. Searches to EOF that fail are
# remembered in `_Misses`, so a run of unclosed heredocs or comments costs
# one scan, not one each.

_MAX_TEMPLATE_DEPTH = 32


class _Misses:
    """Searches that already failed. A search that found no terminator
    from offset p finds none from any later offset either."""

    __slots__ = ("heredoc", "comment")

    def __init__(self) -> None:
        self.heredoc: dict[str, int] = {}
        self.comment: int | None = None


def _heredoc_end(text: str, pos: int, ident: str, misses: _Misses) -> int:
    """Index just past the line that closes a heredoc whose body starts at
    `pos`; `pos` itself when the terminator is missing, so the body is
    lexed as code."""
    failed = misses.heredoc.get(ident)
    if failed is not None and pos >= failed:
        return pos
    m = re.compile(
        r'^[ \t]*' + re.escape(ident) + r'[ \t]*\r?$', re.MULTILINE
    ).search(text, pos)
    if m is None:
        misses.heredoc[ident] = pos
        return pos
    return m.end()


def _comment_end(text: str, i: int, misses: _Misses) -> int | None:
    """`i` is just past `/*`. Index past the closing `*/`, or None."""
    if misses.comment is not None and i >= misses.comment:
        return None
    j = text.find("*/", i)
    if j < 0:
        misses.comment = i
        return None
    return j + 2


def _next_line(text: str, i: int) -> int:
    nl = text.find("\n", i)
    return len(text) if nl < 0 else nl


def _template_end(text: str, i: int, limit: int, depth: int) -> int | None:
    """`i` is just past a `${` / `%{` in a quoted string whose line ends at
    `limit`. Return the index past its `}`, or None when it does not close
    on that line. The interpolation is an expression, so it is lexed like
    code: comments and strings inside it cannot move the depth."""
    braces = 1
    while i < limit:
        m = _LEX_RE.match(text, i, limit)
        kind = m.lastgroup
        i = m.end()
        if kind == "bc":
            j = text.find("*/", i, limit)
            if j < 0:
                return None
            i = j + 2
        elif kind in ("lc", "hd"):
            return None  # runs past the line, so the template cannot close
        elif kind == "dq":
            end, _plain, ok = _lex_string_end(text, m.start(), limit, depth + 1)
            if not ok:
                return None
            i = end
        elif kind == "lb":
            braces += 1
        elif kind == "rb":
            braces -= 1
            if braces == 0:
                return i
    return None


def _lex_string_end(
    text: str, i: int, limit: int, depth: int = 0,
) -> tuple[int, bool, bool]:
    """`text[i]` is an opening `"` on a line that ends at `limit`. Return
    ``(end, plain, closed)``: the index past the closing quote, whether
    the literal had no escapes or templates, and whether it closed at
    all. An unclosed string ends at `limit` instead of eating the file."""
    if depth > _MAX_TEMPLATE_DEPTH:
        return limit, False, False
    plain = True
    i += 1
    while True:
        m = _STRING_STOP_RE.search(text, i, limit)
        if m is None:
            return limit, False, False
        i = m.start()
        ch = m.group()
        if ch == '"':
            return i + 1, plain, True
        if ch == "\\":
            plain = False
            i += 2
        elif text.startswith(ch + ch + "{", i):  # `$${` / `%%{` escapes
            plain = False
            i += 3
        elif text.startswith("{", i + 1):
            plain = False
            end = _template_end(text, i + 2, limit, depth)
            if end is None:
                return limit, False, False
            i = end
        else:
            i += 1


@functools.lru_cache(maxsize=1024)
def _block_index(text: str) -> tuple[tuple, ...]:
    """Every block that is structurally top-level in ``text``, in source
    order, as ``(keyword, labels, start_pos, open_pos, end_pos)`` — the
    keyword, the header's `{`, and one past the closing `}`.

    A header at depth 0 is always a candidate. A top-level keyword that
    starts a line *inside* a block that never closes is one too, so one
    unbalanced block does not hide every block after it. A block that
    never closes is dropped.
    """
    n = len(text)
    braces: list[list] = []   # [parent_index, closed, header]
    stack: list[int] = []
    pending: list | None = []  # tokens of the statement being read
    line_start = True          # `pending` began at the start of a line
    line_end = -1              # end of the line holding `i`, computed lazily
    misses = _Misses()
    i = 0
    while i < n:
        m = _LEX_RE.match(text, i)
        kind = m.lastgroup
        i = m.end()
        if kind == "nl":
            pending, line_start = [], True
        elif kind == "bc":
            end = _comment_end(text, i, misses)
            if end is None:
                i, pending = _next_line(text, m.start()), None
            else:
                i = end
        elif kind in ("ws", "lc"):
            pass
        elif kind == "hd":
            end = _heredoc_end(text, i, m.group("hid"), misses)
            # No terminator: resume on the line after `<<EOT`, which the
            # token already consumed the newline of.
            pending, line_start = ([], True) if end == i else (None, False)
            i = end
        elif kind == "dq":
            if m.start() > line_end:
                line_end = _next_line(text, m.start())
            end, plain, _closed = _lex_string_end(text, m.start(), line_end)
            label = text[m.start() + 1 : end - 1]
            if pending and plain and _BLOCK_LABEL_RE.match(label):
                pending.append((label, m.start()))
            else:
                pending = None
            i = end
        elif kind == "id":
            if pending is not None:
                pending.append((m.group(), m.start()))
        elif kind == "lb":
            header = None
            if pending and _IDENT_LABEL_RE.match(pending[0][0]):
                kw = pending[0][0]
                if not stack or (line_start and kw in _TOP_LEVEL_KEYWORDS):
                    header = (
                        kw, tuple(t for t, _ in pending[1:]),
                        pending[0][1], m.start(),
                    )
            braces.append([stack[-1] if stack else -1, False, header])
            stack.append(len(braces) - 1)
            pending, line_start = [], False
        elif kind == "rb":
            if stack:
                braces[stack.pop()][1] = i
            pending, line_start = [], False
        else:
            pending = None
    out = []
    eligible: list[bool] = []
    for parent, closed, header in braces:
        ok = parent < 0 or (not braces[parent][1] and eligible[parent])
        eligible.append(ok)
        if ok and closed and header is not None:
            kw, labels, start, open_pos = header
            out.append((kw, labels, start, open_pos, closed))
    return tuple(out)



def comments_only(text: str) -> str:
    """``text`` with everything but comments blanked to spaces; newlines
    are kept, so line numbers hold. Lexed like `_block_index`: a ``#``
    inside a string, template or heredoc body is not a comment, and an
    unterminated ``/*`` is not one either."""
    out: list[str] = []
    last = 0  # text[last:] not yet copied to `out`
    n = len(text)
    i, line_end = 0, -1
    misses = _Misses()

    def keep(a: int, b: int) -> None:
        nonlocal last
        out.append(re.sub(r"[^\n]", " ", text[last:a]))
        out.append(text[a:b])
        last = b

    while i < n:
        m = _LEX_RE.match(text, i)
        kind = m.lastgroup
        i = m.end()
        if kind == "lc":
            keep(m.start(), i)
        elif kind == "bc":
            end = _comment_end(text, i, misses)
            if end is None:
                i = _next_line(text, m.start())
            else:
                keep(m.start(), end)
                i = end
        elif kind == "hd":
            i = _heredoc_end(text, i, m.group("hid"), misses)
        elif kind == "dq":
            if m.start() > line_end:
                line_end = _next_line(text, m.start())
            i = _lex_string_end(text, m.start(), line_end)[0]
    out.append(re.sub(r"[^\n]", " ", text[last:]))
    return "".join(out)


def _matching_blocks(text: str, regex: re.Pattern):
    for kw, labels, start, open_pos, end in _block_index(text):
        canon = kw + "".join(f' "{lbl}"' for lbl in labels) + " {"
        m = regex.match(canon)
        if m is None or m.end() != len(canon):
            continue
        yield m, start, open_pos, end


@functools.lru_cache(maxsize=1024)
def _newline_offsets(text: str) -> tuple[int, ...]:
    """Offsets of every newline in `text` (memoised per text)."""
    return tuple(m.start() for m in re.finditer("\n", text))


def _line_at(text: str, pos: int) -> int:
    """1-based line of offset `pos`. A binary search over the cached
    newline offsets: `text.count("\n", 0, pos)` per block re-scanned
    the file from the top each time, quadratic in its size (~40 % of a
    4,000-resource scan)."""
    return bisect.bisect_left(_newline_offsets(text), pos) + 1


def find_blocks(text: str, regex: re.Pattern) -> list[dict]:
    """Find top-level blocks. Returns list of {start_line,end_line,body,header}.

    `regex` is matched against the canonical header
    (``resource "type" "name" {``), so it selects block kinds and
    supplies `groups`; where the block sits comes from `_block_index`.
    """
    blocks = []
    for m, start_pos, open_pos, end_pos in _matching_blocks(text, regex):
        blocks.append(
            {
                "groups": m.groups(),
                "start_line": _line_at(text, start_pos),
                "header_match": m,
                "body": text[open_pos + 1 : end_pos - 1],
                "block_text": text[start_pos:end_pos],
                "start_pos": start_pos,
                "end_pos": end_pos,
            }
        )
    return blocks


def find_simple_blocks(text: str, regex: re.Pattern) -> list[dict]:
    """Find top-level blocks for patterns without named groups (moved, import)."""
    return [
        {
            "start_line": _line_at(text, start_pos),
            "body": text[open_pos + 1 : end_pos - 1],
        }
        for _m, start_pos, open_pos, end_pos in _matching_blocks(text, regex)
    ]


# ---- Top-level masking (regex fallback) ---------------------------------

_HEREDOC_START_RE = re.compile(r'<<-?[ \t]*([A-Za-z_][\w-]*)[ \t]*\r?\n')


def _string_end(text: str, i: int) -> int:
    """Index just past the double-quoted string starting at ``text[i]``.
    Handles ``\\`` escapes, ``$${`` / ``%%{`` literals and ``${ }`` /
    ``%{ }`` interpolations (which may contain nested strings and braces).
    An unterminated string ends at the newline."""
    n = len(text)
    j = i + 1
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return j
        if ch == '"':
            return j + 1
        if ch in "$%" and text.startswith(ch * 2 + "{", j):
            j += 3
            continue
        if ch in "$%" and j + 1 < n and text[j + 1] == "{":
            depth = 1
            j += 2
            while j < n and depth:
                c = text[j]
                if c == '"':
                    j = _string_end(text, j)
                    continue
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            continue
        j += 1
    return n


@functools.lru_cache(maxsize=4096)
def _mask_to_top_level(body: str) -> str:
    """Return ``body`` with everything that is not top-level code blanked
    to spaces (newlines kept, so offsets and line numbers line up):
    comments, string literals, heredoc bodies, and the contents of every
    ``{}`` / ``[]`` / ``()``. The brackets that open and close a top-level
    construct are kept, so ``ingress {`` and ``tags = {`` stay visible but
    nothing inside them does."""
    out = list(body)
    n = len(body)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    depth = 0
    i = 0
    while i < n:
        ch = body[i]
        nxt = body[i + 1] if i + 1 < n else ""
        if ch == "#" or (ch == "/" and nxt == "/"):
            j = body.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif ch == "/" and nxt == "*":
            j = body.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif ch == '"':
            j = _string_end(body, i)
            blank(i, j)
            i = j
        elif ch == "<" and nxt == "<" and _HEREDOC_START_RE.match(body, i):
            m = _HEREDOC_START_RE.match(body, i)
            assert m is not None
            term = re.compile(rf'(?m)^[ \t]*{re.escape(m.group(1))}[ \t]*\r?$')
            t = term.search(body, m.end())
            j = n if t is None else t.end()
            blank(i, j)
            i = j
        elif ch in "{[(":
            if depth:
                out[i] = " "
            depth += 1
            i += 1
        elif ch in "}])":
            depth = max(0, depth - 1)
            if depth:
                out[i] = " "
            i += 1
        else:
            if depth and ch != "\n":
                out[i] = " "
            i += 1
    return "".join(out)


@functools.lru_cache(maxsize=4096)
def mask_comments_and_heredocs(body: str) -> str:
    """Return ``body`` with comments and heredoc bodies blanked to spaces
    (newlines kept, so offsets and line numbers line up). Ordinary string
    literals are kept — regexes over a body commonly match quoted values
    like ``"allow-all"`` — but they are stepped over, so a ``#`` inside a
    string is not taken for a comment. Used by ``resource_body_contains``
    so commented-out code and heredoc text (scripts, policy documents)
    don't match (tasks/hcl-parser-migration.md §9)."""
    out = list(body)
    n = len(body)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        ch = body[i]
        nxt = body[i + 1] if i + 1 < n else ""
        if ch == "#" or (ch == "/" and nxt == "/"):
            j = body.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif ch == "/" and nxt == "*":
            j = body.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
        elif ch == '"':
            i = _string_end(body, i)
        elif ch == "<" and nxt == "<" and _HEREDOC_START_RE.match(body, i):
            m = _HEREDOC_START_RE.match(body, i)
            assert m is not None
            term = re.compile(rf'(?m)^[ \t]*{re.escape(m.group(1))}[ \t]*\r?$')
            t = term.search(body, m.end())
            j = n if t is None else t.end()
            blank(i, j)
            i = j
        else:
            i += 1
    return "".join(out)

def block_has_arg(body: str, arg: str) -> bool:
    """Check if a block body has a top-level argument named `arg`.

    Matches both attribute assignments (`arg = value`) and nested block
    declarations (`arg {`, `arg "label" {`), since some arguments appear
    as blocks in HCL. Top-level only: a same-named key inside a nested
    block or an object attribute (e.g. a `tags` map key) does not count,
    and nor does text inside strings, heredocs or comments. Rules that
    mean a nested setting use `block_has_nested_path` / `nested_path`.

    This is the regex fallback; resource checks prefer the parse tree via
    `resource_has_path` (tasks/hcl-parser-migration.md §4.4, §4.7).
    """
    pat = re.compile(rf'(?m)^[ \t]*{re.escape(arg)}[ \t]*[={{]')
    return bool(pat.search(_mask_to_top_level(body)))


def _hcl_object_to_json(text: str) -> dict | None:
    """Best-effort convert an HCL object literal (used inside ``jsonencode(...)``)
    to a Python dict — the regex fallback for a file the parser could not
    read (the tree path is `_iam_policy.decode_policy`).

    HCL accepts JSON-like object literals but with `=` instead of `:`,
    bareword keys, newline-separated members and bare references. We do a
    small, conservative rewrite to canonical JSON, then ``json.loads`` it:
    comments are blanked, keys quoted, a comma added between members on
    separate lines, and a bare reference (``aws_s3_bucket.b.arn``) becomes
    a ``"${...}"`` string, as the parse tree renders it. Returns None on
    any parse failure — callers fall back gracefully rather than raising.
    """
    if not text or not text.strip().startswith("{"):
        return None
    s = strip_hcl_context(text)
    # `key = value` / `"key" = value` → `"key": value`
    s = re.sub(r'(?m)(^|[{,\n]\s*)([A-Za-z_][\w-]*)\s*=\s*', r'\1"\2": ', s)
    s = re.sub(r'(?m)(^|[{,\n]\s*)("[^"\n]*")\s*=\s*', r'\1\2: ', s)
    # A bare reference value → `"${ref}"` (true/false/null stay literals).
    s = re.sub(
        r'([:\[,]\s*)(?!(?:true|false|null)\b)([A-Za-z_][\w-]*(?:\.[\w*-]+|\[\d+\])+)'
        r'(?=\s*[,\]}\n])',
        r'\1"${\2}"', s,
    )
    # Members on separate lines: a value end then a newline then the next
    # member or element needs a comma.
    s = re.sub(r'(["\d\]}]|\btrue|\bfalse|\bnull)([ \t]*\n\s*)(?=["{\[\d-]|true|false|null)',
               r'\1,\2', s)
    # Strip trailing commas before `}` or `]` (HCL allows them, JSON doesn't).
    s = re.sub(r',(\s*[}\]])', r'\1', s)
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return None


def block_arg_value(body: str, arg: str) -> str | None:
    """Return the literal value of a top-level argument, stripped of quotes/comments.

    Top-level only: an ``arg = ...`` inside a nested block, string, heredoc
    or comment is not the block's own argument. (Before parser migration
    Step 5 this took the *first* ``arg =`` at any depth — e.g. a Cloud
    Armor ``rate_limit_threshold { count = 100 }`` was read as the
    resource's ``count``.)

    Heredoc-bearing values (`arg = <<-EOF\\n...\\nEOF`) are not handled by the
    regex path — the trailing `<<-EOF` is returned verbatim, which is rarely
    useful — so heredoc-bearing bodies are first tried through python-hcl2,
    which extracts the heredoc structurally and returns the actual string.

    Moved from detect.py into `_hcl.py` in Session F so that
    `_cross_resource.py` can call this without a circular import back
    into detect.
    """
    if "<<" in body:
        v = _hcl2_block_arg_value(body, arg)
        if v is not None:
            return v
    m = re.search(
        rf'(?m)^[ \t]*{re.escape(arg)}[ \t]*=', _mask_to_top_level(body),
    )
    if not m:
        return None
    line_start = body.rfind("\n", 0, m.start()) + 1
    return _first_arg_value(body[line_start:], arg)


def _first_arg_value(body: str, arg: str) -> str | None:
    """Value text of the first ``arg = ...`` line in ``body`` (any depth),
    with multi-line collections extended to their closer and trailing
    comments / quotes stripped. Callers locate the right line first —
    see `block_arg_value`."""
    m = re.search(rf'(?m)^\s*{re.escape(arg)}\s*=\s*(.+?)\s*$', body)
    if not m:
        return None
    # Multi-line collection / object / parenthesised value: the
    # single-line regex above only captures the first physical line, so
    # `actions = [\n  "s3:*",\n  "*",\n]` would return just `"["`. When
    # the value opens a bracketed construct, extend the capture to its
    # matching close via the quote-aware brace_walk so callers (e.g. the
    # IAM wildcard analyser's `'"*"' in actions` test) see the whole
    # literal. Single-line bracketed values are unchanged (brace_walk
    # finds the closer on the same line); unbalanced input falls back to
    # the single-line value below.
    _closer = {"[": "]", "{": "}", "(": ")"}
    open_ch = body[m.start(1)]
    if open_ch in _closer:
        coll_end = brace_walk(body, m.start(1), opens=open_ch, closes=_closer[open_ch])
        if coll_end is not None:
            return body[m.start(1):coll_end].strip()
    # Strip a trailing comment — `#`, `//` or `/* */` — outside any
    # string. String-aware (`strip_hcl_context`), and HCL has no
    # single-quoted strings, so an apostrophe never starts one. (The
    # previous walker only ran when the value held a quote, so
    # `default = true // note` kept its comment.)
    val = strip_hcl_context(m.group(1)).strip()
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    return val


def block_has_nested_path(body: str, path: str, *, every: bool = True) -> bool:
    """Check if a nested HCL path like `settings.backup_configuration.enabled` is set.

    Regex fallback for `attrs_has_path`, with the same rules as far as text
    allows: each segment is looked up at the top level of the enclosing
    block; a segment may be a nested block (`head {`) or an object
    attribute (`head = {`); and when the segment occurs more than once,
    the rest of the path must hold for every instance (any one instance
    with ``every=False``). (The
    list-of-objects form `head = [{...}]` is only handled on the tree
    path.)
    """
    head, _, rest = path.partition(".")
    if not rest:
        return block_has_arg(body, head)
    masked = _mask_to_top_level(body)
    opener = re.compile(rf'(?m)^[ \t]*{re.escape(head)}[ \t]*(?:=[ \t]*)?\{{')
    instances = []
    for m in opener.finditer(masked):
        open_pos = m.end() - 1
        # Inside the top-level mask every nested bracket is blanked, so
        # the next `}` is this construct's own closer.
        close_pos = masked.find("}", open_pos + 1)
        if close_pos < 0:
            continue
        instances.append(body[open_pos + 1:close_pos])
    check = all if every else any
    return bool(instances) and check(
        block_has_nested_path(i, rest, every=every) for i in instances
    )

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
        # Find the outer dynamic block boundary (quote/comment-aware).
        outer_after = brace_walk(body, m.end() - 1)
        if outer_after is None:
            result.append(body[m.start():])
            break
        outer_end = outer_after - 1  # index of the matching `}`
        outer_body = body[m.end():outer_end]
        # Extract the content { ... } block inside the dynamic block
        content_m = re.search(r'(?m)^\s*content\s*\{', outer_body)
        if content_m:
            content_after = brace_walk(outer_body, content_m.end() - 1)
            content_end = content_after - 1 if content_after is not None else None
            if content_end is not None:
                content_body = outer_body[content_m.end():content_end]
                result.append(f'{block_name} {{{content_body}}}')
            else:
                result.append(body[m.start():outer_end + 1])
        else:
            result.append(body[m.start():outer_end + 1])
        i = outer_end + 1
    return ''.join(result)
