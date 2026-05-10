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
    """Replace comments with equal-length whitespace so line numbers
    of remaining code match the original. String literals are left alone —
    patterns that would false-positive on strings should be HCL-aware
    (resource_arg, hcl_attr) rather than grep."""
    def blank(match: re.Match) -> str:
        s = match.group(0)
        # Preserve the first captured char if it's not part of the comment.
        lead = match.group(1) if match.lastindex else ""
        return lead + " " * (len(s) - len(lead))
    out = _LINE_COMMENT_RE.sub(blank, text)
    out = _BLOCK_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), out)
    return out


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
        in_dq = in_sq = False
        cut = None
        for idx, ch in enumerate(val):
            if ch == '"' and not in_sq:
                in_dq = not in_dq
            elif ch == "'" and not in_dq:
                in_sq = not in_sq
            elif ch == "#" and not in_dq and not in_sq:
                cut = idx
                break
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
