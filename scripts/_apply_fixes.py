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

from _hcl import brace_walk


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
    # Round-30.13 — the in-line quote-aware walker that R30.12 added
    # has moved to `_hcl.brace_walk`. Calling the shared helper here
    # (a) deduplicates 4 sites that were doing the same thing, and
    # (b) lets the `_hcl` unit tests cover the edge cases (quoted
    # braces in IAM ARNs, escaped quotes, single-quoted strings) for
    # every consumer at once.
    #
    # If the first line doesn't open a multi-line map literal, the
    # whole value is on that line; return it. We detect "no multi-line
    # follow-through" by walking just the first line — if `brace_walk`
    # closes within it (or finds no opening brace), there's no need
    # to extend.
    first_line_end = brace_walk(first_line, 0)
    if first_line_end is not None and first_line_end == len(first_line):
        return first_line.strip()
    if "{" not in first_line:
        return first_line.strip()
    # Otherwise extend through the full text to the matching `}`.
    end_pos = brace_walk(text, 0)
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
    for i in range(start, end + 1):
        line = lines[i]
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

            # Don't patch a block the forward scan overshot into (e.g. the
            # next resource, when finding.line pointed at a preceding blank
            # line). Only vetoes a clear resource-address mismatch.
            if not _line_opens_finding_resource(modified[start_idx], resource_addr):
                continue

            if kind == "resource_missing_arg" and arg:
                block_end = find_block_end_in_lines(modified, start_idx)
                if block_end is None:
                    continue
                # Idempotency — skip if the argument is already present at
                # the block's top level. Without this, re-running
                # --apply-fixes (or a fix that doesn't clear the finding)
                # inserts a duplicate attribute and breaks `terraform validate`.
                if _block_has_top_level_arg(modified, start_idx, block_end, arg):
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
                # Prefer the resource's own (depth-1) attribute so a
                # same-named key inside a nested block isn't clobbered.
                # Fall back to the first match at any depth for rules whose
                # target legitimately sits in a nested block (no regression).
                attr_re = re.compile(rf'^\s*{re.escape(arg)}\s*=')
                target_li = None
                depth = 0
                for li in range(start_idx, block_end + 1):
                    if attr_re.match(modified[li]):
                        if depth == 1:
                            target_li = li
                            break
                        if target_li is None:
                            target_li = li
                    for ch in modified[li]:
                        if ch == '{':
                            depth += 1
                        elif ch == '}':
                            depth -= 1
                if target_li is not None:
                    line = modified[target_li]
                    indent = line[:len(line) - len(line.lstrip())]
                    modified[target_li] = f"{indent}{fix_line}\n"
                    total_applied += 1

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
