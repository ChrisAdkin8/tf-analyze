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
import re
import shutil
import sys
from pathlib import Path


def fix_hcl_body(fix_hcl: str) -> str:
    """Strip outer ``resource "x" "y" { ... }`` wrapper, returning just the body."""
    m = re.match(r'^\s*resource\s+"[^"]+"\s+"[^"]+"\s*\{(.*)\}\s*$', fix_hcl, re.DOTALL)
    return m.group(1) if m else fix_hcl


def fix_line_for_arg(fix_hcl: str, arg: str) -> str | None:
    """Extract the ``arg = value`` expression from a ``fix_hcl`` snippet.

    Handles single-line attributes and multi-line map literals
    (``arg = { ... }``). Returns None if ``arg`` does not appear as an
    assignment (use :func:`fix_block_for_nested_arg` for block syntax).
    """
    body = fix_hcl_body(fix_hcl)
    start_m = re.search(rf'(?m)^\s*{re.escape(arg)}\s*=', body)
    if not start_m:
        return None
    text = body[start_m.start():]
    newline_pos = text.find('\n')
    first_line = text if newline_pos == -1 else text[:newline_pos]
    # Round-5 audit fix #5 — quote-aware brace depth. The previous
    # `first_line.count('{') - first_line.count('}')` counted braces
    # inside string literals as block-structure characters. A fix
    # snippet like `value = "with { in string"` falsely registered as
    # a multi-line map literal; one like `value = "with } in string"
    # { real = 1 }` registered as already-balanced and got truncated.
    # This is the same class the 12 `detect_in_file` detector branches
    # share — pulling one site forward of the deferred `_brace_walk`
    # extraction. The walker tracks `in_dq` / `in_sq` with backslash
    # awareness, mirroring `_hcl.block_arg_value`.
    def _quote_aware_brace_depth(s: str) -> int:
        depth = 0
        in_dq = in_sq = False
        prev = ""
        for ch in s:
            escaped = prev == "\\"
            if ch == '"' and not in_sq and not escaped:
                in_dq = not in_dq
            elif ch == "'" and not in_dq and not escaped:
                in_sq = not in_sq
            elif ch == '{' and not in_dq and not in_sq:
                depth += 1
            elif ch == '}' and not in_dq and not in_sq:
                depth -= 1
            prev = ch
        return depth

    # If the first line opens more braces than it closes (ignoring
    # braces inside strings), this is a multi-line map literal —
    # extend to the matching `}`.
    if _quote_aware_brace_depth(first_line) <= 0:
        return first_line.strip()
    depth = 0
    end_pos = None
    in_dq = in_sq = False
    prev = ""
    for i, ch in enumerate(text):
        escaped = prev == "\\"
        if ch == '"' and not in_sq and not escaped:
            in_dq = not in_dq
        elif ch == "'" and not in_dq and not escaped:
            in_sq = not in_sq
        elif ch == '{' and not in_dq and not in_sq:
            depth += 1
        elif ch == '}' and not in_dq and not in_sq:
            depth -= 1
            if depth == 0:
                end_pos = i + 1
                break
        prev = ch
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
    depth = 0
    end_pos = None
    for i, ch in enumerate(text):
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end_pos = i + 1
                break
    if end_pos is None:
        return None
    return text[:end_pos]


def reindent_fix_snippet(raw: str, indent: str) -> list[str]:
    """Re-indent a fix snippet (single or multi-line) for insertion.

    Strips the base indentation of the first line from every line,
    then prepends ``indent``. Returns a list of newline-terminated
    strings ready for list insertion via ``modified[end:end] = ...``.
    """
    lines = raw.split('\n')
    base_len = len(lines[0]) - len(lines[0].lstrip())
    base = ' ' * base_len
    result = []
    for line in lines:
        stripped = line[base_len:] if line.startswith(base) else line
        result.append(f"{indent}{stripped}\n")
    return result


def find_block_end_in_lines(lines: list[str], start: int) -> int | None:
    """0-based index of the line containing the closing ``}`` of the block
    that opens at or after ``start``. Handles nested braces.
    """
    depth = 0
    for i in range(start, len(lines)):
        for ch in lines[i]:
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


def handle_apply_fixes(
    args: object,
    findings: list[dict],
    entries: list[dict],
    dry_run: bool,
) -> None:
    """Apply (or preview) ``fix_hcl`` patches for every fixable finding.

    Processes findings grouped by file, in reverse line order so that
    insertions at later lines do not shift earlier positions. Creates
    ``.bak`` backups before writing when not in dry-run mode.

    A rule with either ``fix_hcl_minimal`` or ``fix_hcl`` is patchable;
    ``fix_hcl_minimal`` (R30.10) is preferred when both are present —
    it's the stripped-down patch snippet without the surrounding
    resource declaration, which makes the regex-based insert/replace
    below more reliable on complex rules.
    """
    entry_map = {e["id"]: e for e in entries}

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

        with open(path) as fh:
            original_lines = fh.readlines()
        modified = original_lines[:]

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
            pattern = None
            for pat in entry.get("patterns", []):
                if pat.get("resource", "") == resource_type:
                    pattern = pat
                    break

            if not pattern:
                continue

            kind = pattern.get("kind", "")
            arg = pattern.get("arg", "")
            # find_blocks' RESOURCE_START allows a leading blank line
            # before the resource keyword, so start_line may be 1 too
            # low. Advance to the line that actually contains the
            # opening `{`.
            start_idx = finding.get("line", 1) - 1
            while start_idx < len(modified) - 1 and '{' not in modified[start_idx]:
                start_idx += 1

            if kind == "resource_missing_arg" and arg:
                block_end = find_block_end_in_lines(modified, start_idx)
                if block_end is None:
                    continue
                indent = block_indent(modified, start_idx, block_end)
                raw = fix_line_for_arg(fix_hcl, arg) or fix_block_for_nested_arg(fix_hcl, arg)
                if not raw:
                    continue
                modified[block_end:block_end] = reindent_fix_snippet(raw, indent)
                total_applied += 1

            elif kind in ("resource_arg", "hcl_attr"):
                block_end = find_block_end_in_lines(modified, start_idx)
                if block_end is None:
                    continue
                fix_line = fix_line_for_arg(fix_hcl, arg)
                if not fix_line:
                    continue
                attr_re = re.compile(rf'(?m)^\s*{re.escape(arg)}\s*=')
                for li in range(start_idx, block_end + 1):
                    if attr_re.match(modified[li]):
                        indent = modified[li][:len(modified[li]) - len(modified[li].lstrip())]
                        modified[li] = f"{indent}{fix_line}\n"
                        total_applied += 1
                        break

        if modified == original_lines:
            continue

        diff_lines = list(difflib.unified_diff(
            original_lines, modified,
            fromfile=f"{file_path}.orig",
            tofile=file_path,
            lineterm="",
        ))

        if dry_run:
            for dl in diff_lines:
                print(dl)
        else:
            shutil.copy2(path, str(path) + ".bak")
            with open(path, "w") as fh:
                fh.writelines(modified)
            print(f"# patched {file_path}", file=sys.stderr)

    action = "would apply" if dry_run else "applied"
    print(
        f"# apply-fixes: {action} {total_applied} fix(es) across {len(by_file)} file(s)",
        file=sys.stderr,
    )
