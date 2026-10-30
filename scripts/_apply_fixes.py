"""Auto-fix helpers for ``--apply-fixes``.

Seven cohesive functions that together drive the fix-application
pipeline:

* :func:`fix_hcl_body` — strip the outer ``resource "..." "..." { ... }``
  wrapper from a ``fix_hcl`` catalogue snippet, returning just the
  body. Snippets in the catalogue carry the wrapper for readability;
  the patcher only needs the inside.
* :func:`fix_line_for_arg` — extract a single ``arg = value`` line
  from a snippet, supporting multi-line map literals.
* :func:`fix_block_for_nested_arg` — extract a nested
  ``arg { ... }`` block.
* :func:`reindent_fix_snippet` — strip the snippet's intrinsic
  indentation and prepend the target file's indent.
* :func:`find_block_end_in_lines` — brace-match through a list of
  lines to locate the line containing the closing ``}`` of a block
  that opens at index ``start``.
* :func:`block_indent` — detect the indentation string used by
  attributes inside an HCL block.
* :func:`fix_blocker` — why a snippet must not be pasted into a module:
  it names something the module does not declare, or holds a placeholder.
  :func:`snippet_refusal` adds the rule for nested snippets; `--apply-fixes`
  decides with it, and so, through :func:`fix_refusal`, does
  :func:`annotate_fix_blockers`, which records the answer on findings for
  the paths that offer a fix as one click (PR suggestions, quick fixes).
* :func:`handle_apply_fixes` — top-level driver. Groups fixable
  findings by file, processes in reverse line order so later
  insertions don't shift earlier positions, writes ``.bak`` backups
  before mutating on disk (unless ``dry_run``), and lists what it left
  for a person.

Extracted from ``detect.py`` as the **fourteenth modularisation seam**.
Pure-functional except for ``handle_apply_fixes``, which is the only
function that touches the filesystem.
"""
from __future__ import annotations

import difflib
import functools
import io
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from _hcl import (
    _read_normalized,
    _string_end,
    brace_walk,
    mask_comments,
    mask_comments_and_heredocs,
)
from _tfjson import is_tf_source, read_tf_source


def fix_hcl_body(fix_hcl: str) -> str:
    """Strip outer ``resource "x" "y" { ... }`` wrapper, returning just the body."""
    m = re.match(r'^\s*resource\s+"[^"]+"\s+"[^"]+"\s*\{(.*)\}\s*$', fix_hcl, re.DOTALL)
    return m.group(1) if m else fix_hcl


def fix_line_for_arg(fix_hcl: str, arg: str) -> str | None:
    """Extract the ``arg = value`` expression from a ``fix_hcl`` snippet.

    Handles single-line attributes and multi-line values that open with
    a map, list or call (``arg = { ... }``, ``[ ... ]``,
    ``jsonencode( ... )``). Returns None if ``arg`` does not appear as an
    assignment (use :func:`fix_block_for_nested_arg` for block syntax).
    """
    body = fix_hcl_body(fix_hcl)
    start_m = re.search(rf'(?m)^\s*{re.escape(arg)}\s*=', body)
    if not start_m:
        return None
    text = body[start_m.start():]
    newline_pos = text.find('\n')
    first_line = text if newline_pos == -1 else text[:newline_pos]
    # Round-30.13 — the in-line quote-aware walker that R30.12 added
    # has moved to `_hcl.brace_walk`. Calling the shared helper here
    # (a) deduplicates 4 sites that were doing the same thing, and
    # (b) lets the `_hcl` unit tests cover the edge cases (quoted
    # braces in IAM ARNs, escaped quotes, single-quoted strings) for
    # every consumer at once.

    # The value's first bracket decides how far it runs: `{ … }` (a map),
    # `[ … ]` (a list) or `( … )` (a call such as `jsonencode(`). If it
    # does not close on the first line, extend through the text to the
    # matching close; otherwise the whole value is on that line. Only `{`
    # used to be followed, so a multi-line list in a fix was cut to its
    # first line (`enabled_cluster_log_types = [`) — invalid HCL.
    # Only a bracket that starts the value (or a call's `(`) counts, never
    # one inside a string such as `name = "a[b"`.
    opener = re.match(r'[^=]*=\s*(?:[\w.]+\s*)?([{\[(])', first_line)
    if opener is None:
        return first_line.strip()
    pos, ch = opener.start(1), opener.group(1)
    closes = {"{": "}", "[": "]", "(": ")"}[ch]
    if brace_walk(first_line, pos, opens=ch, closes=closes) is not None:
        return first_line.strip()
    end_pos = brace_walk(text, pos, opens=ch, closes=closes)
    if end_pos is None:
        return first_line.strip()
    # Raw (unstripped) so reindent_fix_snippet has the first-line base_len.
    return text[:end_pos]


def fix_block_for_nested_arg(fix_hcl: str, arg: str) -> str | None:
    """Extract the ``arg { ... }`` nested block from a ``fix_hcl`` snippet.

    Returns the raw block text with the leading whitespace of the
    first line intact (used by :func:`reindent_fix_snippet` to
    determine base indentation).
    """
    body = fix_hcl_body(fix_hcl)
    start_m = re.search(rf'(?m)^\s*{re.escape(arg)}\s*\{{', body)
    if not start_m:
        return None
    text = body[start_m.start():]
    # Round-30.13 — shared helper. The old in-line walker wasn't quote-
    # aware (any `}` inside a string would falsely close the block);
    # the helper handles that automatically.
    end_pos = brace_walk(text, 0)
    if end_pos is None:
        return None
    return text[:end_pos]


def reindent_fix_snippet(
    raw: str, indent: str, eol: str = "\n", unit: str | None = None,
) -> list[str]:
    """Re-indent a fix snippet (single or multi-line) for insertion.

    Strips the base indentation of the first line from every line,
    then prepends ``indent``. With ``unit`` (the file's own indentation
    step, e.g. four spaces or a tab), each two-space step of the
    snippet's inner indentation (the catalogue's `terraform fmt` style)
    becomes one ``unit``, so a fix in a tab-indented file is not mixed
    tabs and spaces. Returns a list of `eol`-terminated strings ready for
    list insertion via ``modified[end:end] = ...``.
    """
    lines = raw.split('\n')
    base_len = len(lines[0]) - len(lines[0].lstrip())
    base = ' ' * base_len
    result = []
    for line in lines:
        stripped = line[base_len:] if line.startswith(base) else line
        if unit is not None:
            body = stripped.lstrip(" ")
            lead = len(stripped) - len(body)
            stripped = unit * (lead // 2) + " " * (lead % 2) + body
        result.append(f"{indent}{stripped.rstrip(chr(13))}{eol}")
    return result


@functools.lru_cache(maxsize=16)
def _blanked(source: str) -> str:
    """The text of `code_lines`, once per file state: every step of a patch
    asks again, and a scan tries a patch per finding."""
    text = mask_comments_and_heredocs(source)
    out = list(text)
    i = 0
    while True:
        i = text.find('"', i)
        if i < 0:
            break
        end = _string_end(text, i)
        for k in range(i + 1, max(i + 1, end - 1)):
            if out[k] not in "\r\n":
                out[k] = " "
        i = max(end, i + 1)
    return "".join(out)


def code_lines(lines: list[str]) -> list[str]:
    """`lines` with comments, heredoc bodies and string contents blanked to
    spaces (line count and lengths unchanged), so brace counting and
    argument matching see only HCL structure: a ``}`` in ``# see } below``
    or in ``"{"`` no longer closes a block (CLAUDE.md: raw brace walkers
    must be comment-aware)."""
    masked = _blanked("".join(lines))
    result, pos = [], 0
    for line in lines:
        result.append(masked[pos:pos + len(line)])
        pos += len(line)
    return result


def find_block_end_in_lines(
    lines: list[str], start: int, code: list[str] | None = None,
) -> int | None:
    """0-based index of the line containing the closing ``}`` of the block
    that opens at or after ``start``. Handles nested braces; braces in
    comments, strings and heredocs do not count (`code_lines`). `code` is
    `code_lines(lines)`, if the caller has it.
    """
    depth = 0
    code = code_lines(lines) if code is None else code
    for i in range(start, len(lines)):
        for ch in code[i]:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i
    return None


def block_indent(lines: list[str], start: int, end: int) -> str:
    """Detect the indentation string used by attributes inside an HCL block."""
    for i in range(start + 1, end):
        stripped = lines[i].lstrip()
        if stripped and not stripped.startswith('}') and not stripped.startswith('#'):
            return lines[i][:len(lines[i]) - len(stripped)]
    return "  "  # fallback: 2 spaces


def _block_has_top_level_arg(lines: list[str], start: int, end: int, arg: str) -> bool:
    """True if ``arg`` is already set as a top-level (depth-1) attribute or
    nested-block opener of the resource that opens at line ``start``.

    Used by the ``resource_missing_arg`` path so re-running ``--apply-fixes``
    (or applying a report whose fix didn't clear the finding) doesn't insert
    a *second* ``arg = …`` line and produce HCL that fails ``terraform
    validate`` with "Attribute redefined". Depth tracking matches
    ``find_block_end_in_lines`` (brace count over lines) so a same-named
    attribute inside a *nested* block isn't mistaken for a top-level one.
    """
    arg_re = re.compile(rf'^\s*{re.escape(arg)}\s*[={{]')
    depth = 0
    code = code_lines(lines)
    for i in range(start, end + 1):
        line = code[i]
        if depth == 1 and arg_re.match(line):
            return True
        for ch in line:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
    return False


def _line_opens_finding_resource(line: str, resource_addr: str) -> bool:
    """Guard against patching the wrong block.

    The forward scan for the opening ``{`` can overshoot into the *next*
    resource when ``finding.line`` points at a blank line just before it.
    Returns ``False`` only when ``line`` clearly opens a ``resource``/``data``
    block whose type/name mismatch ``resource_addr`` — that's the
    overshoot signature. Conservative: returns ``True`` when it can't tell
    (no address, non-``resource``/``data`` header) so correct fixes are
    never blocked; it only vetoes a clear mismatch.
    """
    parts = resource_addr.split(".")
    if len(parts) < 2:
        return True
    rtype, rname = parts[-2], parts[-1]
    m = re.match(r'\s*(?:resource|data)\s+"([^"]+)"\s+"([^"]+)"', line)
    if not m:
        return True
    return m.group(1) == rtype and m.group(2) == rname


_HEREDOC_RE = re.compile(r'=\s*<<-?\s*"?(\w+)"?\s*$')


def _value_end_line(lines: list[str], code: list[str], li: int) -> int:
    """0-based index of the last line of the ``arg = value`` that starts
    on line `li`. A value whose brackets (``[`` ``{`` ``(``) do not close
    on that line runs to the line where they do; a heredoc runs to its
    terminator. Brackets are counted on `code` (strings and comments
    blanked), so ``"a[b"`` does not open one.

    Replacing only line `li` left the rest of a multi-line value behind
    (``"api",`` and ``]`` after a new list): invalid HCL.
    """
    m = _HEREDOC_RE.search(lines[li].rstrip("\r\n"))
    if m:
        for j in range(li + 1, len(lines)):
            if lines[j].strip() == m.group(1):
                return j
        return li
    depth = 0
    eq = code[li].find("=")
    for j in range(li, len(lines)):
        for ch in code[j][eq + 1:] if j == li else code[j]:
            if ch in "[{(":
                depth += 1
            elif ch in "]})":
                depth -= 1
        if depth <= 0:
            return j
    return li


# ---- What a fix may not paste -------------------------------------------------

_DECL_RE = re.compile(
    r'(?m)^[ \t]*(?:(resource|data)[ \t]+"([\w-]+)"[ \t]+"([\w-]+)"'
    r'|(variable|module)[ \t]+"([\w-]+)")'
)
_LOCALS_RE = re.compile(r'(?m)^[ \t]*locals\s*\{')
_LOCAL_NAME_RE = re.compile(r'^\s*([\w-]+)\s*=')

# What an expression can reference. A resource type always holds a `_`,
# which keeps out `each.key`, `count.index`, `path.module`, `self.id`.
_REFERENCE_RE = re.compile(
    r'(?<![\w.])(?<!\w-)(?:(var|local|module)\.([\w-]+)'
    r'|data\.([\w-]+)\.([\w-]+)'
    r'|([a-z][a-z0-9]*_[\w-]*)\.([A-Za-z_][\w-]*))'
)
# `${ ... }` and the template directive `%{ if ... }`, in strings and heredocs.
_INTERPOLATION_RE = re.compile(r'(?<![$%])[$%]\{([^}]*)\}')
_STRING_RE = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
_BLOCK_HEADER_RE = re.compile(r'(?m)^[ \t]*(?:resource|data|module|variable|output|provider)[ \t]+".*$')

# A value that stands in for one the user has to supply: the word `example`
# as a path or name segment (`projects/example/...`), the IP ranges kept for
# documentation (RFC 5737), and the usual fill-me-in markers.
_PLACEHOLDER_RE = re.compile(
    r'(?i)(?<![a-z0-9])example(?![a-z0-9])'
    r'|\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.'
    r'|(?<![a-z0-9])(?:change|replace)[-_]?me(?![a-z0-9])'
    r'|(?<![a-z0-9])your[-_]'
    r'|<[^<>${}]+>|\bTODO\b|\bx{4,}\b|\b(?:123456789012|0{12})\b|\b0{8}-0{4}-'
)

_EXAMPLE_REASON = "its values are examples: choose your own"
_NESTED_REASON = "it belongs in a nested block: add it by hand"
_NO_PATCH_REASON = "no automatic patch for this check"
_IT_DEPENDS = object()


def declared_names(text: str) -> set[str]:
    """Everything `text` (HCL) declares, as references spell it:
    ``aws_kms_key.logs``, ``data.aws_ami.a``, ``var.x``, ``local.y``,
    ``module.z``. Comments and heredocs do not declare anything."""
    code = mask_comments_and_heredocs(text)
    names: set[str] = set()
    for m in _DECL_RE.finditer(code):
        kind, rtype, rname, single, sname = m.groups()
        if kind:
            name = f"{'data.' if kind == 'data' else ''}{rtype}.{rname}"
        else:
            name = f"{'var' if single == 'variable' else 'module'}.{sname}"
        names.add(name)
        # `aws_kms_key.logs[]`: it has instances, so a reference needs an index.
        opening = code.find("{", m.end())
        end = brace_walk(code, opening) if opening >= 0 else None
        if end and single != "variable" and {"count", "for_each"} & _top_level_names(
            code[opening + 1:end - 1]
        ):
            names.add(f"{name}[]")
    for m in _LOCALS_RE.finditer(code):
        end = brace_walk(code, m.end() - 1)
        if end is not None:
            names.update(f"local.{n}" for n in _top_level_names(code[m.end():end - 1]))
    return names


def _top_level_names(body: str) -> set[str]:
    """The names assigned directly in a block `body`, not in anything nested."""
    names: set[str] = set()
    depth = 0
    for line in code_lines(body.splitlines(keepends=True)):
        name = _LOCAL_NAME_RE.match(line) if depth == 0 else None
        if name:
            names.add(name.group(1))
        depth += sum(line.count(c) for c in "[{(") - sum(line.count(c) for c in "]})")
    return names


def module_declarations(directory: Path) -> set[str]:
    """`declared_names` of a Terraform module: every source file directly
    in `directory`. A file that can't be read declares nothing, which can
    only hold a fix back."""
    names: set[str] = set()
    try:
        files = sorted(p for p in directory.iterdir() if p.is_file() and is_tf_source(p))
    except OSError:
        return names
    for path in files:
        try:
            names |= declared_names(read_tf_source(path, _read_normalized))
        except (OSError, ValueError):
            continue
    return names


def _expressions(snippet: str) -> str:
    """The parts of `snippet` that are expressions: its code, and what is in
    ``${...}`` / ``%{...}`` in its strings and heredocs. Plain string
    contents are not expressions."""
    code = "".join(code_lines(snippet.splitlines(keepends=True)))
    return code + " " + " ".join(_INTERPOLATION_RE.findall(mask_comments(snippet)))


def _references(snippet: str) -> list[tuple[str, bool]]:
    """``(reference, whether an index follows it)`` for each one in `snippet`."""
    text = _expressions(snippet)
    found = []
    for m in _REFERENCE_RE.finditer(text):
        prefix, name, dtype, dname, rtype, rname = m.groups()
        if prefix:
            ref = f"{prefix}.{name}"
        elif dtype:
            ref = f"data.{dtype}.{dname}"
        else:
            ref = f"{rtype}.{rname}"
        found.append((ref, text.startswith(("[", ".*"), m.end())))
    return found


def undeclared_references(snippet: str, declared: set[str]) -> list[str]:
    """What `snippet` references that is declared neither in `declared` nor
    by `snippet` itself."""
    known = declared | declared_names(snippet)
    return list(dict.fromkeys(ref for ref, _ in _references(snippet) if ref not in known))


def unindexed_references(snippet: str, declared: set[str]) -> list[str]:
    """References in `snippet`, with no index, to something with `count` or
    `for_each`: ``aws_kms_key.logs.arn`` is an error when `logs` has instances."""
    return list(dict.fromkeys(
        ref for ref, indexed in _references(snippet)
        if not indexed and f"{ref}[]" in declared
    ))


def placeholder_values(snippet: str) -> list[str]:
    """String values in `snippet` that stand in for a real one. A block's
    labels (``resource "aws_x" "example"``) are names, not values."""
    code = _BLOCK_HEADER_RE.sub("", mask_comments_and_heredocs(snippet))
    return [m.group(1) for m in _STRING_RE.finditer(code) if _PLACEHOLDER_RE.search(m.group(1))]


def fix_blocker(
    snippet: str, declared: set[str], block_args: set[str] | None = None,
) -> str | None:
    """Why `snippet` must not go into a module declaring `declared`, or
    None. Terraform rejects a reference to something undeclared, and a
    made-up value is not a fix even when it validates. `block_args`, when
    the target block is known, holds which of `count` / `for_each` it has:
    `each.key` means nothing in a block without `for_each`."""
    missing = undeclared_references(snippet, declared)
    if missing:
        return f"references {', '.join(missing)}, not declared in this module"
    unindexed = unindexed_references(snippet, declared)
    if unindexed:
        return f"references {', '.join(unindexed)} without an index, and it has count or for_each"
    if block_args is not None:
        code = _expressions(snippet)
        for word, arg in (("each", "for_each"), ("count", "count")):
            if arg not in block_args and re.search(rf'(?<![\w.]){word}\.', code):
                return f"uses {word}.*, and this block has no {arg}"
    placeholders = placeholder_values(snippet)
    if placeholders:
        return f"holds the placeholder value {placeholders[0]!r}: use a real one"
    return None


def snippet_refusal(
    snippet: str, nested: bool, declared: set[str], block_args: set[str] | None = None,
) -> str | None:
    """Why `--apply-fixes` won't paste this snippet, or None: the one
    decision, for the patcher and for the paths that offer a fix as one
    click."""
    return _NESTED_REASON if nested else fix_blocker(snippet, declared, block_args)


def _patch_snippet(fix_hcl: str, kind: str, arg: str) -> tuple[str, bool] | None:
    """``(text, nested)``: what a pattern of `kind` on `arg` would paste, and
    whether that belongs in a nested block; None if there's nothing to paste."""
    if not arg:
        return None
    if kind == "resource_missing_arg":
        raw = fix_line_for_arg(fix_hcl, arg) or fix_block_for_nested_arg(fix_hcl, arg)
        return (raw, _nested_in_fix(fix_hcl, arg)) if raw else None
    if kind in ("resource_arg", "hcl_attr"):
        raw = fix_line_for_arg(fix_hcl, arg)
        return (raw, False) if raw else None
    return None


def fix_refusal(entry: dict, resource_type: str, declared: set[str]) -> str | None:
    """Why a finding of `entry` on `resource_type` can't be taken as a fix
    in a module declaring `declared`, or None. A rule with a patch for this
    type answers as `--apply-fixes` would: fine if any pattern's snippet is
    (which one applies depends on the block; see `annotate_fix_blockers`).
    One without has only its whole `fix_hcl` to offer, judged as it stands."""
    if entry.get("fix_hcl_example"):
        return _EXAMPLE_REASON
    fix = entry.get("fix_hcl_minimal") or entry.get("fix_hcl") or ""
    answers = _pattern_answers(entry, resource_type, declared)
    if not answers:
        return fix_blocker(fix, declared)
    return None if None in answers else answers[0]


def _pattern_answers(entry: dict, resource_type: str, declared: set[str]) -> list[str | None]:
    """`snippet_refusal` of each of `entry`'s patches for `resource_type`."""
    fix = entry.get("fix_hcl_minimal") or entry.get("fix_hcl") or ""
    answers = []
    for pat in entry.get("patterns") or []:
        if pat.get("resource", "") != resource_type:
            continue
        snippet = _patch_snippet(fix, pat.get("kind", ""), pat.get("arg", ""))
        if snippet is not None:
            answers.append(snippet_refusal(*snippet, declared))
    return answers


def _file_lines(path: str, texts: dict | None, cache: dict) -> tuple[list[str], list[str]] | None:
    """``(lines, code_lines(lines))`` of `path` (from `texts`, an editor's
    unsaved buffers, if there), once; None if unreadable or not patchable.
    Lines end at line endings only: `str.splitlines` also breaks on form
    feeds and U+2028, and a quick fix would then miss its line."""
    if path not in cache:
        lines = None
        if texts and path in texts:
            lines = io.StringIO(texts[path], newline="").readlines()
        elif not path.endswith(".tf.json"):
            try:
                with open(path, encoding="utf-8", newline="") as fh:
                    lines = fh.readlines()
            except (OSError, ValueError):
                pass
        cache[path] = None if lines is None else (lines, code_lines(lines))
    return cache[path]


def _finding_block(
    finding: dict, path_lines: tuple[list[str], list[str]],
) -> tuple[list[str], dict] | None:
    """The lines from the finding's line to the end of its block, and the
    finding renumbered to match: a patch tried on those alone costs its
    block, not the file, so a file's findings stay linear in its size."""
    lines, code = path_lines
    index = int(finding.get("line") or 0) - 1
    if not 0 <= index < len(lines):
        return None
    end = find_block_end_in_lines(lines, index, code)
    return None if end is None else (lines[index:end + 1], {**finding, "line": 1})


def _suggestion(finding: dict, entry: dict, declared: set[str], lines: list[str]) -> str | None:
    """What may replace the finding's line, as a one-click suggestion, or
    None. A suggestion overwrites exactly that line, so the text comes from
    running the patcher on a copy (it has passed `snippet_refusal`), and is
    offered only where it fits that line: the new value when the patch
    replaced that line, or the block's own header followed by the new
    argument when the line opens the block the patch added to. Never a
    catalogue `fix_hcl`, whose `resource "x" "example" {` wrapper would
    overwrite the user's header."""
    index = int(finding.get("line") or 0) - 1
    if not 0 <= index < len(lines):
        return None
    patched = lines[:]
    if _attempt_fix(patched, finding, entry, declared, "\n")[0] is None:
        return None
    start = 0
    while start < len(lines) and start < len(patched) and lines[start] == patched[start]:
        start += 1
    tail = 0
    while (tail < len(lines) - start and tail < len(patched) - start
           and lines[-1 - tail] == patched[-1 - tail]):
        tail += 1
    removed, added = lines[start:len(lines) - tail], patched[start:len(patched) - tail]
    if removed == [lines[index]] and start == index:
        text = "".join(added)
    elif not removed and start > index and code_lines(lines)[index].rstrip().endswith("{"):
        text = lines[index] + "".join(added)
    else:
        return None
    return text.replace("\r\n", "\n").rstrip("\n")


def _scope_of(path: Path, cache: dict) -> set[str]:
    """`module_declarations` of the folder `path` is in (or is), once."""
    folder = path if path.is_dir() else path.parent
    if folder not in cache:
        cache[folder] = module_declarations(folder)
    return cache[folder]


def annotate_fix_blockers(
    findings: list[dict], entries: list[dict], texts: dict | None = None,
    suggestions: bool = False,
) -> None:
    """Set ``fix_manual_reason`` on each finding whose fix can't be taken in
    its module, and with `suggestions`, ``fix_suggestion`` on each that can
    be taken in one click (`_suggestion`). Every path that offers a fix as
    one click (``--mode pr-review``, the GitHub Action and its template via
    ``--fix-suggestions``, the editor's quick fix on request) pastes
    ``fix_suggestion`` or nothing; only they pay for running the patcher.
    `texts`: ``{path: text}`` where the file on disk isn't the one scanned."""
    entry_map = {e["id"]: e for e in entries}
    cache: dict = {}
    files: dict = {}
    reasons: dict[tuple, str | None] = {}
    for f in findings:
        entry = entry_map.get(f["id"]) or {}
        fix = entry.get("fix_hcl")
        if not fix:
            continue
        path = Path(str(f.get("file", "")))
        resource_type = str(f.get("resource", "")).split(".")[0]
        scope = _scope_of(path, cache)
        key = (f["id"], path.parent, resource_type)
        if key not in reasons:
            answers = () if entry.get("fix_hcl_example") else _pattern_answers(
                entry, resource_type, scope,
            )
            reasons[key] = (
                _IT_DEPENDS if None in answers and any(answers)
                else fix_refusal(entry, resource_type, scope)
            )
        reason = reasons[key]
        block = None
        if reason is _IT_DEPENDS or (suggestions and not reason):
            path_lines = _file_lines(str(f.get("file", "")), texts, files)
            block = _finding_block(f, path_lines) if path_lines else None
        if reason is _IT_DEPENDS:
            reason = _attempt_fix(block[0][:], block[1], entry, scope, "\n")[1] if block else None
        if reason:
            f["fix_manual_reason"] = reason
        elif suggestions and block:
            suggestion = _suggestion(block[1], entry, scope, block[0])
            if suggestion:
                f["fix_suggestion"] = suggestion


def _nested_in_fix(fix_hcl: str, arg: str) -> bool:
    """Whether `arg` sits inside a nested block of the snippet. Its line
    means nothing at the top of the resource: Athena's `encryption_option`
    pasted there is "Unsupported argument"."""
    body = fix_hcl_body(fix_hcl)
    start = re.search(rf'(?m)^\s*{re.escape(arg)}\s*[={{]', body)
    if not start:
        return False
    code = "".join(code_lines(body[:start.start()].splitlines(keepends=True)))
    return sum(code.count(c) for c in "[{(") > sum(code.count(c) for c in "]})")


def _write_atomic(path: Path, text: str) -> None:
    """Write `text` to `path` as UTF-8 through a temporary file in the same
    directory and `os.replace`, keeping the file's permissions. An
    interrupted run leaves the original or the new file, never half of
    one (it used to rewrite in place)."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        shutil.copymode(path, tmp)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _unsafe_write_reason(path: Path, roots: list[Path]) -> str | None:
    """Why patching `path` (and writing its ``.bak``) is unsafe, or None.

    A scanned repo is untrusted input: a symlinked ``main.tf`` or
    ``main.tf.bak`` would make the patcher write through the link to any
    file the user can write (e.g. ``main.tf.bak -> ~/.bashrc``)."""
    bak = Path(str(path) + ".bak")
    if path.is_symlink():
        return "file is a symlink"
    if bak.is_symlink() or (bak.exists() and not bak.is_file()):
        return f"{bak.name} is a symlink or not a regular file"
    if roots and not any(path.resolve().is_relative_to(r.resolve()) for r in roots):
        return "file resolves outside the scan target"
    return None


def _backup_path(path: Path) -> Path:
    """The first free name of ``<file>.bak``, ``<file>.bak.1``, … — an
    existing backup is never overwritten, so a second run keeps the true
    original. A dangling symlink counts as taken (`os.path.lexists`)."""
    candidate = Path(str(path) + ".bak")
    n = 0
    while os.path.lexists(candidate):
        n += 1
        candidate = Path(f"{path}.bak.{n}")
    return candidate


def _split_inline_block(lines: list[str], start: int, eol: str) -> None:
    """Give the block opening on line `start` its own lines: its ``{`` ends
    a line and its closing ``}`` starts one. The fixes below insert before
    the closing line and match attributes at the start of a line, so for
    ``resource "x" "y" {}`` (or ``{ a = 1 }``) they put the new lines
    *above* the header, outside the block, and every re-run added them
    again. Edits `lines` in place; a block already laid out is untouched.
    """
    code = code_lines(lines)
    depth, open_col, close = 0, None, None
    for i in range(start, len(lines)):
        for col, ch in enumerate(code[i]):
            if ch == "{":
                if depth == 0 and i == start:
                    open_col = col
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    close = (i, col)
                    break
        if close or (i == start and open_col is None):
            break
    if open_col is None or close is None:
        return
    head = lines[start]
    head_indent = head[:len(head) - len(head.lstrip())]
    end, close_col = close
    # Closing brace first: it is on the same or a later line, so splitting
    # it leaves `open_col` valid.
    if code[end][:close_col].strip():
        raw = lines[end]
        lines[end:end + 1] = [raw[:close_col].rstrip() + eol, head_indent + raw[close_col:]]
    rest = lines[start][open_col + 1:]
    if code[start][open_col + 1:len(lines[start]) - len(eol)].strip():
        lines[start:start + 1] = [
            lines[start][:open_col + 1] + eol, head_indent + "  " + rest.lstrip(),
        ]


def _apply_pattern(
    modified: list[str], start_idx: int, kind: str, arg: str, fix_hcl: str, eol: str,
    vet=None,
) -> bool:
    """Apply one pattern's fix to the resource block opening at
    `start_idx`, editing `modified` in place. True if it changed it. An
    inline block is split onto its own lines first (`_split_inline_block`),
    and kept split only when the fix then changes it.

    `vet(snippet, nested, block_args)` sees the exact text about to go in
    and returns False to refuse it; `nested` says it belongs in a nested
    block, `block_args` is which of `count` / `for_each` the block has."""
    trial = modified[:]
    _split_inline_block(trial, start_idx, eol)
    if not _apply_pattern_to_block(trial, start_idx, kind, arg, fix_hcl, eol, vet):
        return False
    modified[:] = trial
    return True


def _apply_pattern_to_block(
    modified: list[str], start_idx: int, kind: str, arg: str, fix_hcl: str, eol: str,
    vet=None,
) -> bool:
    """`_apply_pattern` for a block whose braces are on their own lines."""
    block_end = find_block_end_in_lines(modified, start_idx)
    if block_end is None:
        return False

    def block_args() -> set[str]:
        return {a for a in ("count", "for_each")
                if _block_has_top_level_arg(modified, start_idx, block_end, a)}

    if kind == "resource_missing_arg" and arg:
        # Idempotency — skip if the argument is already present at the
        # block's top level. Without this, re-running --apply-fixes (or a
        # fix that doesn't clear the finding) inserts a duplicate
        # attribute and breaks `terraform validate`.
        if _block_has_top_level_arg(modified, start_idx, block_end, arg):
            return False
        indent = block_indent(modified, start_idx, block_end)
        snippet = _patch_snippet(fix_hcl, kind, arg)
        if snippet is None:
            return False
        accepted = vet(*snippet, block_args()) if vet else True
        if snippet[1] or not accepted:
            return False
        modified[block_end:block_end] = reindent_fix_snippet(snippet[0], indent, eol, unit=indent)
        return True
    if kind in ("resource_arg", "hcl_attr") and arg:
        fix_line = fix_line_for_arg(fix_hcl, arg)
        if not fix_line or (vet and not vet(fix_line, False, block_args())):
            return False
        # Prefer the resource's own (depth-1) attribute so a same-named
        # key inside a nested block isn't clobbered. Fall back to the
        # first match at any depth for rules whose target legitimately
        # sits in a nested block (no regression).
        attr_re = re.compile(rf'^\s*{re.escape(arg)}\s*=')
        code = code_lines(modified)
        target_li = None
        depth = 0
        for li in range(start_idx, block_end + 1):
            if attr_re.match(code[li]):
                if depth == 1:
                    target_li = li
                    break
                if target_li is None:
                    target_li = li
            for ch in code[li]:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
        if target_li is None:
            return False
        line = modified[target_li]
        indent = line[:len(line) - len(line.lstrip())]
        # Replace the whole old value, and re-indent the new one (a
        # multi-line fix kept the snippet's own indentation and `\n`).
        value_end = _value_end_line(modified, code, target_li)
        unit = block_indent(modified, start_idx, block_end)
        new = reindent_fix_snippet(fix_line, indent, eol, unit=unit)
        if new == modified[target_li:value_end + 1]:
            return False
        modified[target_li:value_end + 1] = new
        return True
    return False


def _attempt_fix(
    modified: list[str], finding: dict, entry: dict, scope: set[str], eol: str,
) -> tuple[str | None, str | None]:
    """Try `entry`'s fix for `finding` on `modified`, in place. Returns
    ``(argument patched, None)`` or ``(None, why not)``."""
    fix_hcl = entry.get("fix_hcl_minimal") or entry.get("fix_hcl", "")
    resource_addr = finding.get("resource", "")
    resource_type = resource_addr.split(".")[0] if "." in resource_addr else ""
    patterns = [
        pat for pat in entry.get("patterns", [])
        if pat.get("resource", "") == resource_type
    ]
    if not patterns:
        return None, _NO_PATCH_REASON

    # `line` is the resource keyword's line; the opening `{` can
    # sit on a later line (e.g. after a comment), so advance to
    # the line that actually contains it.
    start_idx = finding.get("line", 1) - 1
    code = code_lines(modified)
    while start_idx < len(modified) - 1 and '{' not in code[start_idx]:
        start_idx += 1

    # Don't patch a block the forward scan overshot into (e.g. the
    # next resource, when finding.line pointed at a preceding blank
    # line). Only vetoes a clear resource-address mismatch.
    if not _line_opens_finding_resource(modified[start_idx], resource_addr):
        return None, "could not locate the resource block"

    refused: list[str] = []

    def vet(snippet: str, nested: bool, block_args: set[str]) -> bool:
        reason = snippet_refusal(snippet, nested, scope, block_args)
        if reason:
            refused.append(reason)
        return reason is None

    for pat in patterns:
        if _apply_pattern(
            modified, start_idx, pat.get("kind", ""), pat.get("arg", ""), fix_hcl, eol, vet,
        ):
            return pat.get("arg", ""), None
    return None, refused[0] if refused else _NO_PATCH_REASON


def handle_apply_fixes(
    args: object,
    findings: list[dict],
    entries: list[dict],
    dry_run: bool,
) -> None:
    """Apply (or preview) ``fix_hcl`` patches for every fixable finding.

    Processes findings grouped by file, in reverse line order so that
    insertions at later lines do not shift earlier positions. Before
    writing (not in dry-run mode) it saves the file to a backup that never
    overwrites an earlier one (`_backup_path`). Files are read and written
    as UTF-8 with line endings untouched, so CRLF stays CRLF, and written
    atomically (`_write_atomic`).

    Each of the rule's patterns on the finding's resource type is tried in
    order until one changes the block — the finding does not record which
    pattern fired, and the first one (say "argument missing") may not
    apply when another ("argument set to false") is what matched.

    A rule with either ``fix_hcl_minimal`` or ``fix_hcl`` is patchable;
    ``fix_hcl_minimal`` (R30.10) is preferred when both are present —
    it's the stripped-down patch snippet without the surrounding
    resource declaration, which makes the regex-based insert/replace
    below more reliable on complex rules.

    A snippet goes in only if `fix_blocker` passes it for the file's own
    module. Everything left undone is reported, one
    ``# apply-fixes: manual: ...`` line each with its reason, so the
    "applied N" count is what really happened and the rest can be picked up
    by hand. That goes for ``dry_run`` too.
    """
    entry_map = {e["id"]: e for e in entries}
    roots = [Path(t) for t in getattr(args, "targets", None) or []]

    manual: list[tuple[dict, str]] = []
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        entry = entry_map.get(f["id"])
        if not entry or not (entry.get("fix_hcl_minimal") or entry.get("fix_hcl")):
            continue
        fp = f.get("file", "")
        if not fp:
            manual.append((f, "the finding names no file"))
            continue
        # Example values (`fix_hcl_example: true`) need a person to choose
        # the real ones; pasting `Owner = "platform-team"` is not a fix.
        if entry.get("fix_hcl_example"):
            manual.append((f, _EXAMPLE_REASON))
            continue
        by_file.setdefault(fp, []).append(f)

    total_applied = 0
    covered = 0
    files_changed = 0
    scopes: dict = {}

    for file_path in sorted(by_file):
        path = Path(file_path)
        # is_file() is stricter than exists() — it filters out
        # directories too. "Absent resource" findings (kind=
        # resource_missing_arg with no corresponding declaration)
        # carry the *target directory* in `file`, not a real source
        # file. exists() returned True for those and we'd fall through
        # to open(), which then raised IsADirectoryError.
        if not path.is_file():
            manual.extend((f, "no file to patch: the fix is a new resource")
                          for f in by_file[file_path])
            continue
        # A `.tf.json` file is scanned as rendered HCL; an HCL fix snippet
        # cannot be spliced into JSON, so it is reported but not patched.
        if path.name.endswith(".tf.json"):
            manual.extend((f, "HCL fixes can't be patched into JSON syntax")
                          for f in by_file[file_path])
            continue
        unsafe = _unsafe_write_reason(path, roots)
        if unsafe:
            print(f"WARN: apply-fixes: skipping {file_path}: {unsafe}", file=sys.stderr)
            manual.extend((f, unsafe) for f in by_file[file_path])
            continue

        # Terraform source is UTF-8; the locale's encoding (cp1252 on
        # Windows) could fail on, or rewrite, non-ASCII text.
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                original_lines = fh.readlines()
        except UnicodeDecodeError:
            print(f"WARN: apply-fixes: skipping {file_path}: not UTF-8", file=sys.stderr)
            manual.extend((f, "file is not UTF-8") for f in by_file[file_path])
            continue
        scope = _scope_of(path, scopes)
        added: set[tuple] = set()
        modified = original_lines[:]
        crlf = sum(line.endswith("\r\n") for line in original_lines)
        eol = "\r\n" if crlf * 2 > len(original_lines) else "\n"

        # Process findings in reverse line order — insertions at later
        # lines don't affect positions of earlier ones.
        file_findings = sorted(
            by_file[file_path], key=lambda x: x.get("line", 0), reverse=True,
        )

        for finding in file_findings:
            entry = entry_map.get(finding["id"])

            resource_addr = finding.get("resource", "")
            applied_arg, reason = _attempt_fix(modified, finding, entry, scope, eol)
            if applied_arg is not None:
                total_applied += 1
                added.add((resource_addr, applied_arg))
            # Another rule's fix in this run may have added the same
            # argument (two rules want `retention_in_days`): that one is
            # done. Only then: an argument the file already had is why the
            # patcher stopped, not a fix.
            elif any((resource_addr, pat.get("arg", "")) in added
                     for pat in entry.get("patterns", [])):
                covered += 1
            else:
                manual.append((finding, reason))

        if modified == original_lines:
            continue
        files_changed += 1

        if dry_run:
            # Lines keep their own endings, so the default lineterm gives
            # a patch `git apply` / `patch -p0` accept (lineterm="" with
            # newline-terminated lines printed every line twice).
            sys.stdout.writelines(difflib.unified_diff(
                original_lines, modified,
                fromfile=f"{file_path}.orig",
                tofile=file_path,
            ))
        else:
            original = path.read_bytes()
            backup = _backup_path(path)
            with open(backup, "xb") as fh:  # "x": never follow or clobber
                fh.write(original)
            _write_atomic(path, "".join(modified))
            print(f"# patched {file_path} (backup: {backup.name})", file=sys.stderr)

    action = "would apply" if dry_run else "applied"
    print(
        f"# apply-fixes: {action} {total_applied} fix(es) across {files_changed} file(s)",
        file=sys.stderr,
    )
    if covered:
        print(f"# apply-fixes: {covered} finding(s) covered by a fix above", file=sys.stderr)
    if manual:
        print(f"# apply-fixes: {len(manual)} fix(es) left for you to do by hand:",
              file=sys.stderr)
    for f, reason in manual:
        print(
            f"# apply-fixes: manual: {f['id']} {f.get('file', '')}:{f.get('line', 0)} "
            f"{f.get('resource', '')}: {reason}",
            file=sys.stderr,
        )
