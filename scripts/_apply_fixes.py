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
* :func:`handle_apply_fixes` — top-level driver. Groups fixable
  findings by file, processes in reverse line order so later
  insertions don't shift earlier positions, writes ``.bak`` backups
  before mutating on disk (unless ``dry_run``).

Extracted from ``detect.py`` as the **fourteenth modularisation seam**.
Pure-functional except for ``handle_apply_fixes``, which is the only
function that touches the filesystem.
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from _hcl import _string_end, brace_walk, mask_comments_and_heredocs


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


def code_lines(lines: list[str]) -> list[str]:
    """`lines` with comments, heredoc bodies and string contents blanked to
    spaces (line count and lengths unchanged), so brace counting and
    argument matching see only HCL structure: a ``}`` in ``# see } below``
    or in ``"{"`` no longer closes a block (CLAUDE.md: raw brace walkers
    must be comment-aware)."""
    text = mask_comments_and_heredocs("".join(lines))
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
    masked = "".join(out)
    result, pos = [], 0
    for line in lines:
        result.append(masked[pos:pos + len(line)])
        pos += len(line)
    return result


def find_block_end_in_lines(lines: list[str], start: int) -> int | None:
    """0-based index of the line containing the closing ``}`` of the block
    that opens at or after ``start``. Handles nested braces; braces in
    comments, strings and heredocs do not count (`code_lines`).
    """
    depth = 0
    code = code_lines(lines)
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


def _apply_pattern(
    modified: list[str], start_idx: int, kind: str, arg: str, fix_hcl: str, eol: str,
) -> bool:
    """Apply one pattern's fix to the resource block opening at
    `start_idx`, editing `modified` in place. True if it changed it."""
    block_end = find_block_end_in_lines(modified, start_idx)
    if block_end is None:
        return False
    if kind == "resource_missing_arg" and arg:
        # Idempotency — skip if the argument is already present at the
        # block's top level. Without this, re-running --apply-fixes (or a
        # fix that doesn't clear the finding) inserts a duplicate
        # attribute and breaks `terraform validate`.
        if _block_has_top_level_arg(modified, start_idx, block_end, arg):
            return False
        indent = block_indent(modified, start_idx, block_end)
        raw = fix_line_for_arg(fix_hcl, arg) or fix_block_for_nested_arg(fix_hcl, arg)
        if not raw:
            return False
        modified[block_end:block_end] = reindent_fix_snippet(raw, indent, eol, unit=indent)
        return True
    if kind in ("resource_arg", "hcl_attr") and arg:
        fix_line = fix_line_for_arg(fix_hcl, arg)
        if not fix_line:
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
    """
    entry_map = {e["id"]: e for e in entries}
    roots = [Path(t) for t in getattr(args, "targets", None) or []]

    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file", "")
        if not fp:
            continue
        entry = entry_map.get(f["id"])
        if not entry or not (entry.get("fix_hcl_minimal") or entry.get("fix_hcl")):
            continue
        by_file.setdefault(fp, []).append(f)

    total_applied = 0

    for file_path in sorted(by_file):
        path = Path(file_path)
        # is_file() is stricter than exists() — it filters out
        # directories too. "Absent resource" findings (kind=
        # resource_missing_arg with no corresponding declaration)
        # carry the *target directory* in `file`, not a real source
        # file. exists() returned True for those and we'd fall through
        # to open(), which then raised IsADirectoryError.
        if not path.is_file():
            continue
        # A `.tf.json` file is scanned as rendered HCL; an HCL fix snippet
        # cannot be spliced into JSON, so it is reported but not patched.
        if path.name.endswith(".tf.json"):
            continue
        unsafe = _unsafe_write_reason(path, roots)
        if unsafe:
            print(f"WARN: apply-fixes: skipping {file_path}: {unsafe}", file=sys.stderr)
            continue

        # Terraform source is UTF-8; the locale's encoding (cp1252 on
        # Windows) could fail on, or rewrite, non-ASCII text.
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                original_lines = fh.readlines()
        except UnicodeDecodeError:
            print(f"WARN: apply-fixes: skipping {file_path}: not UTF-8", file=sys.stderr)
            continue
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
            fix_hcl = entry.get("fix_hcl_minimal") or entry.get("fix_hcl", "")
            if not fix_hcl:
                continue

            resource_addr = finding.get("resource", "")
            resource_type = resource_addr.split(".")[0] if "." in resource_addr else ""
            patterns = [
                pat for pat in entry.get("patterns", [])
                if pat.get("resource", "") == resource_type
            ]
            if not patterns:
                continue

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
                continue

            for pat in patterns:
                if _apply_pattern(
                    modified, start_idx, pat.get("kind", ""), pat.get("arg", ""),
                    fix_hcl, eol,
                ):
                    total_applied += 1
                    break

        if modified == original_lines:
            continue

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
        f"# apply-fixes: {action} {total_applied} fix(es) across {len(by_file)} file(s)",
        file=sys.stderr,
    )
