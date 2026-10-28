"""Robustness-tier detector handlers extracted from detect.py (R30.15).

Houses the 14 handlers that detect drift-prone, refactor-fragile or
intent-mismatched configurations: count/for_each anti-patterns,
missing validation blocks, ignore_changes overuse, prod-environment
deletion-protection gaps, and the four ``intent_gap`` sub-checks.

In-file handlers (8):
    variable_type, variable_missing_validation,
    check_block_missing_assert, precondition_missing_error_message,
    count_index_ref, count_index_in_name, count_bool_pattern,
    ignore_changes_overuse

Corpus handlers (6):
    foreach_over_list, foreach_keyset_unstable,
    count_length_unguarded, count_foreach_mix,
    prod_no_deletion_protection, intent_gap
"""
from __future__ import annotations

import functools
import re
from pathlib import Path

from _hcl import (
    _mask_to_top_level,
    _string_end,
    attach_tree_attrs,
    find_blocks,
    mask_comments,
    parse_tf,
    resource_has_path,
    resource_values_at,
    block_arg_value,
    block_has_arg,
    brace_walk,
    block_has_nested_path,
    mask_comments_and_heredocs,
)
from _tfjson import is_tf_source
from detect import (
    InFileCtx,
    CorpusCtx,
    _register_infile,
    _register_corpus,
    RESOURCE_START,
    VARIABLE_START,
    CHECK_START,
    VALIDATION_BLOCK_RE,
    COUNT_GUARD_RE,
    _COUNT_NAME_LIKE_ATTRS,
    _FOREACH_SPLAT_RE,
    _FOREACH_COMPREHENSION_RE,
    _FOREACH_SAFE_SCOPES,
    _PROD_PROTECTED_TYPES,
    _INTENT_SECURITY_NAME_RE,
    _INTENT_FALSE_DEFAULT_RE,
    _INTENT_MUST_TRUE_RE,
    _INTENT_VALIDATION_RE,
    _INTENT_PROD_TAG_RE,
    _INTENT_DEL_PROT_FALSE_RE,
    _INTENT_FORCE_DESTROY_TRUE_RE,
)


# ---- Shared helpers: values from the parse tree, guards over code ------

def _corpus_resources(fp, text: str) -> list[dict]:
    """The file's resource blocks with their parse-tree subtrees attached,
    as `detect_in_file` gives in-file handlers (`attach_tree_attrs`).
    Read-only for callers: one list serves every corpus handler."""
    return _resources_with_attrs(is_tf_source(Path(fp)), text)


@functools.lru_cache(maxsize=1024)
def _resources_with_attrs(parse: bool, text: str) -> list[dict]:
    tree = parse_tf(text)[0] if parse else None
    return attach_tree_attrs(find_blocks(text, RESOURCE_START), tree)


def _top_value(blk: dict, arg: str) -> str | None:
    """The block's own top-level ``arg`` as HCL text — from the parse tree
    when attached, else the regex fallback. Never an ``arg`` in a nested
    or ``dynamic`` block, a comment, a string or a heredoc."""
    if blk.get("attrs") is not None:
        vals = resource_values_at(blk, arg)
        return vals[0] if vals else None
    return block_arg_value(blk["body"], arg)


def _arg_line(blk: dict, arg: str) -> int:
    """Line of the block's top-level ``arg =``; the block's line if not
    found. Read from the block's own text: an in-file ``body`` has had its
    dynamic blocks expanded, which moves lines."""
    text = blk["block_text"]
    open_at = text.index("{") + 1
    m = re.search(
        rf'(?m)^[ \t]*{re.escape(arg)}[ \t]*=', _mask_to_top_level(text[open_at:-1]),
    )
    if not m:
        return blk["start_line"]
    return blk["start_line"] + text.count("\n", 0, open_at + m.start())


_BLOCK_HEADER_LINE_RE = re.compile(r'^\s*[\w-]+(?:\s+(?:"[^"\n]*"|[\w-]+))*\s*\{\s*$')


def _code_lines(text: str) -> tuple[list[str], list[str], list[int]]:
    """``(refs, structure, depths)`` per line of ``text``: `refs` has the
    comments blanked (heredoc text kept — a ``${...}`` there is a real
    reference); `structure` also blanks heredocs; `depths` is the
    ``([{`` nesting depth at the start of each line, strings skipped."""
    refs = mask_comments(text)
    code = mask_comments_and_heredocs(text)
    depths = [0]
    depth, i, n = 0, 0, len(code)
    while i < n:
        ch = code[i]
        if ch == '"':
            i = _string_end(code, i)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "\n":
            depths.append(depth)
        i += 1
    return refs.split("\n"), code.split("\n"), depths


def _guard_context(structure: list[str], depths: list[int], idx: int) -> str:
    """Line ``idx`` plus every earlier line that opens a bracket still
    open at ``idx``, up to the enclosing block header: the code that can
    guard a reference on line ``idx``. ``cond ? (\\n  x[0].id\\n) : null``
    is guarded although the ``?`` is on another line."""
    parts = [structure[idx]]
    low = depths[idx]
    for k in range(idx - 1, -1, -1):
        if low == 0:
            break
        if depths[k] < low:
            if _BLOCK_HEADER_LINE_RE.match(structure[k]):
                break
            parts.append(structure[k])
            low = depths[k]
    return "\n".join(parts)


# ---- In-file handlers ---------------------------------------------------

@_register_infile("variable_type")
def _detect_variable_type(c: InFileCtx) -> list[dict]:
    """``variable_type`` — fire when a variable's declared ``type`` matches the
    rule regex (e.g. catch ``type = any`` or untyped variables).
    """
    rgx_str = c.pat.get("type_regex") or c.pat.get("regex")
    if not rgx_str:
        return []
    regex = re.compile(rgx_str)
    out: list[dict] = []
    for blk in c.variables:
        val = block_arg_value(blk["body"], "type")
        if val is not None and regex.search(val):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"var.{blk['groups'][0]}",
            })
    return out


@_register_infile("variable_missing_validation")
def _detect_variable_missing_validation(c: InFileCtx) -> list[dict]:
    """``variable_missing_validation`` — fire when a variable whose name
    matches ``name_regex`` has no ``validation { ... }`` block.
    """
    name_re = re.compile(c.pat.get("name_regex", ".*"))
    out: list[dict] = []
    for blk in c.variables:
        if not name_re.search(blk["groups"][0]):
            continue
        # Top-level code only: a `validation {` in a comment or a heredoc
        # (`description = <<EOT`) is not a validation block.
        if not block_has_arg(blk["body"], "validation"):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"var.{blk['groups'][0]}",
            })
    return out


@_register_infile("check_block_missing_assert")
def _detect_check_block_missing_assert(c: InFileCtx) -> list[dict]:
    """``check_block_missing_assert`` — TF 1.5+ ``check {}`` block must
    contain at least one ``assert {}``. Without one the block is a
    no-op — usually a half-finished author-time assertion the writer
    forgot to fill in.
    """
    out: list[dict] = []
    for cblk in find_blocks(c.text, CHECK_START):
        # A commented-out `/* assert { ... } */` asserts nothing.
        code = mask_comments_and_heredocs(cblk["body"])
        if not re.search(r'(?m)^\s*assert\s*\{', code):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": cblk["start_line"],
                "resource": f"check.{cblk['groups'][0]}",
            })
    return out


@_register_infile("precondition_missing_error_message")
def _detect_precondition_missing_error_message(c: InFileCtx) -> list[dict]:
    """``precondition_missing_error_message`` — precondition /
    postcondition blocks should always carry an ``error_message``. The
    TF runtime accepts the block without one, but the failure mode is
    a generic "condition failed" with no diagnostic — useless on call.
    """
    pre_re = re.compile(r'(?m)^\s*(precondition|postcondition)\s*\{')
    # Match on the code only (comments and heredocs blanked, offsets kept):
    # a `precondition {` inside `/* */` is not a block.
    code = mask_comments_and_heredocs(c.text)
    out: list[dict] = []
    for m in pre_re.finditer(code):
        end_after = brace_walk(c.text, m.end() - 1)
        if end_after is None:
            continue
        end = end_after - 1
        body = code[m.end():end]
        if not re.search(r'(?m)^\s*error_message\s*=', body):
            line_no = c.text.count("\n", 0, m.start()) + 1
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": line_no,
                "resource": m.group(1),
            })
    return out


@_register_infile("count_index_ref")
def _detect_count_index_ref(c: InFileCtx) -> list[dict]:
    """``count_index_ref`` — find ``X.Y[0].Z`` references to count-using
    resources/modules that aren't guarded by a conditional (ternary,
    try(), length() > 0). Decrementing the count destroys the resource
    at index 0, so unguarded references will fail at apply time.

    Comments are ignored, and a guard counts on the reference's line or
    on any line that opens a bracket around it (`_guard_context`), so a
    ternary split over lines is seen.
    """
    counted_names: set[str] = set()
    for blk in c.resources:
        if block_has_arg(blk["body"], "count"):
            btype, bname = blk["groups"]
            counted_names.add(f"{btype}.{bname}")
    for blk in c.modules:
        if block_has_arg(blk["body"], "count"):
            counted_names.add(f"module.{blk['groups'][0]}")
    if not counted_names:
        return []
    idx_ref_re = re.compile(
        r'((?:[\w-]+\.[\w-]+(?:\.[\w-]+)?)\[0\]\.[\w-]+)'
    )
    refs, structure, depths = _code_lines(c.text)
    out: list[dict] = []
    for idx, line_text in enumerate(refs):
        stripped_line = line_text.lstrip()
        if stripped_line.startswith(("resource ", "module ", "count ")):
            continue
        for m in idx_ref_re.finditer(line_text):
            ref_parts = m.group(1).split("[")[0]
            if ref_parts in counted_names and not COUNT_GUARD_RE.search(
                _guard_context(structure, depths, idx)
            ):
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": idx + 1,
                    "resource": ref_parts,
                })
    return out


@_register_infile("count_index_in_name")
def _detect_count_index_in_name(c: InFileCtx) -> list[dict]:
    """``count_index_in_name`` (R30.17) — flag resources where ``count = N``
    AND a name-like attribute interpolates ``count.index``. The external
    name encodes the positional index, so decrementing count destroys
    real infrastructure (Terraform can't even rebuild on a different
    slot because the external name embeds the old index). Companion to
    ROB-COUNTREF-001 (consumer-side guard).

    Only the resource's own top-level name attributes and its ``Name``
    tag count (read from the parse tree when there is one): not a nested
    block's ``container_name`` or a commented-out line.
    """
    out: list[dict] = []
    for blk in c.resources:
        if not block_has_arg(blk["body"], "count"):
            continue
        for attr in (*_COUNT_NAME_LIKE_ATTRS, "tags.Name"):
            vals = resource_values_at(blk, attr)
            if any(re.search(r'\bcount\.index\b', v) for v in vals):
                btype, bname = blk["groups"]
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": _arg_line(blk, attr.split(".")[0]),
                    "resource": f"{btype}.{bname}",
                })
                break
    return out


def _is_bool_count(val: str | None) -> bool:
    """``count = <expr> ? 1 : 0``, however it is spaced or parenthesised."""
    if val is None:
        return False
    return bool(re.search(r'\?\s*1\s*:\s*0\s*\)*$', " ".join(val.split())))


@_register_infile("count_bool_pattern")
def _detect_count_bool_pattern(c: InFileCtx) -> list[dict]:
    """``count_bool_pattern`` — detect ``count = <expr> ? 1 : 0`` on
    resources and modules. ROB-COUNTBOOL-001 flags the anti-pattern
    because changing the predicate destroys the resource instead of
    leaving it in place. The block's own top-level ``count`` is read
    (parse tree first), so a trailing comment or a ternary split over
    lines still matches and a commented-out ``count`` does not.
    """
    out: list[dict] = []
    for blk in c.resources:
        if _is_bool_count(_top_value(blk, "count")):
            btype, bname = blk["groups"]
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    for blk in c.modules:
        if _is_bool_count(block_arg_value(blk["body"], "count")):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"module.{blk['groups'][0]}",
            })
    return out


def _ignore_changes_items(body: str) -> list[str] | None:
    """The items of a resource's `lifecycle { ignore_changes = [...] }`, or
    None. The block and the list are found with `brace_walk` (string-,
    comment- and nesting-aware): lazy regexes stopped at the first `}`
    (a `precondition {}` before `ignore_changes`) or `]` (an item such
    as `tags["Owner"]`) and under-counted. Items split on commas outside
    strings and brackets."""
    code = mask_comments_and_heredocs(body)
    lc = re.search(r"(?m)^\s*lifecycle\s*\{", code)
    if not lc:
        return None
    lc_end = brace_walk(body, lc.end() - 1)
    if lc_end is None:
        return None
    ic = re.search(r"(?m)^\s*ignore_changes\s*=\s*\[", code[lc.end():lc_end])
    if not ic:
        return None
    open_at = lc.end() + ic.end() - 1
    close_after = brace_walk(body, open_at, opens="[", closes="]")
    if close_after is None:
        return None
    # Read the items from the code: `a, # b, c` lists one attribute.
    inner = code[open_at + 1:close_after - 1]
    items: list[str] = []
    depth, start, i = 0, 0, 0
    while i < len(inner):
        ch = inner[i]
        if ch == '"':
            i = _string_end(inner, i)
            continue
        if ch in "[({":
            depth += 1
        elif ch in "])}":
            depth -= 1
        elif ch == "," and depth == 0:
            items.append(inner[start:i].strip())
            start = i + 1
        i += 1
    items.append(inner[start:].strip())
    return [it for it in items if it]


@_register_infile("ignore_changes_overuse")
def _detect_ignore_changes_overuse(c: InFileCtx) -> list[dict]:
    """``ignore_changes_overuse`` — resources whose
    ``lifecycle.ignore_changes = [...]`` block lists more than
    ``max_attrs`` attributes are likely disabling drift detection by
    attrition rather than declaring a targeted exception. ROB-DRIFT-002
    catches the wildcard ``["*"]`` case; this catches the next failure
    mode at LOW so reviewers see the signal without gating CI.

    Round-30.9 audit fix #20 — the comma-split is quote-aware so a
    value like ``["a,b", "c"]`` correctly counts as two items
    (`_ignore_changes_items`).
    """
    max_attrs = int(c.pat.get("max_attrs", 5))
    out: list[dict] = []
    for blk in find_blocks(c.text, RESOURCE_START):
        body = blk["body"]
        items = _ignore_changes_items(body)
        if items is None:
            continue
        # ROB-DRIFT-002 owns the wildcard case.
        if any(re.fullmatch(r'["\']?\*["\']?', it) or "[*]" in it for it in items):
            continue
        if len(items) > max_attrs:
            btype, bname = blk["groups"]
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
                "context": (
                    f"ignore_changes lists {len(items)} "
                    f"attributes (threshold: {max_attrs})"
                ),
            })
    return out


# ---- Corpus handlers ----------------------------------------------------

@_register_corpus("foreach_over_list")
def _corpus_foreach_over_list(c: CorpusCtx) -> list[dict]:
    """``foreach_over_list`` — fire when a resource uses ``for_each`` with
    a list literal or ``tolist(...)`` — the idiomatic fix is
    ``toset([...])``. A list-keyed for_each silently re-orders on
    upstream changes; toset stabilises. Only the resource's own
    ``for_each``: a ``dynamic`` block's ``for_each`` may be a list.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in _corpus_resources(fp, text):
            val = _top_value(blk, "for_each")
            if val is not None and re.match(r'\[|tolist\s*\(', val.lstrip()):
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
                })
    return out


@_register_corpus("foreach_keyset_unstable")
def _corpus_foreach_keyset_unstable(c: CorpusCtx) -> list[dict]:
    """``foreach_keyset_unstable`` — fire when a ``for_each`` keyset is
    derived from another resource's attribute. Each plan that mutates
    the upstream resource set re-keys this one, forcing destroy/create
    on every existing instance. Classic apply-flicker bug. Only the
    resource's own ``for_each`` (not a ``dynamic`` block's) is read.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in _corpus_resources(fp, text):
            val = _top_value(blk, "for_each")
            if val is None:
                continue
            stmt = "for_each = " + " ".join(val.split())
            leading_ident: str | None = None
            m = _FOREACH_SPLAT_RE.search(stmt)
            if m:
                leading_ident = m.group(1)
            else:
                m2 = _FOREACH_COMPREHENSION_RE.search(stmt)
                if m2:
                    leading_ident = m2.group(1)
            if not leading_ident or leading_ident in _FOREACH_SAFE_SCOPES:
                continue
            out.append({
                "id": c.eid,
                "file": str(fp),
                "line": blk["start_line"],
                "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
                "context": (
                    f"for_each keyset derived from "
                    f"{leading_ident}.* — re-keys on upstream "
                    f"resource-set change"
                ),
            })
    return out


@_register_corpus("count_length_unguarded")
def _corpus_count_length_unguarded(c: CorpusCtx) -> list[dict]:
    """``count_length_unguarded`` — resources declared with
    ``count = length(X)`` whose ``[N]`` / ``[count.index]`` references
    elsewhere are not guarded by length/try/ternary. Only a resource's
    own top-level ``count`` qualifies; comments are ignored, and a guard
    on a line that opens a bracket around the reference counts.
    """
    counted: dict[str, int] = {}
    for fp, text in c.all_files_text.items():
        for blk in _corpus_resources(fp, text):
            val = _top_value(blk, "count")
            if val is not None and re.match(r'\(*\s*length\s*\(', val.lstrip()):
                key = f"{blk['groups'][0]}.{blk['groups'][1]}"
                counted[key] = blk["start_line"]
    out: list[dict] = []
    if not counted:
        return out
    idx_re = re.compile(r'([\w-]+\.[\w-]+)\[(\d+|count\.index)\]')
    for fp, text in c.all_files_text.items():
        refs, structure, depths = _code_lines(text)
        for idx, line_text in enumerate(refs):
            hits = [m for m in idx_re.finditer(line_text) if m.group(1) in counted]
            if not hits:
                continue
            guard = _guard_context(structure, depths, idx)
            if "length(" in guard or "try(" in guard or "?" in guard:
                continue
            for m in hits:
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": idx + 1,
                    "resource": m.group(1),
                })
    return out


@_register_corpus("count_foreach_mix")
def _corpus_count_foreach_mix(c: CorpusCtx) -> list[dict]:
    """``count_foreach_mix`` — per-directory: does any file use ``count``
    AND ``for_each`` on different resources? Anti-pattern that makes
    module consumers deal with both splat and dynamic refs. Flags the
    count users. Only a resource's own top-level ``count`` / ``for_each``
    counts — not a nested block's ``count`` (Cloud Armor's
    ``rate_limit_threshold``) or a ``dynamic`` block's ``for_each``.
    """
    per_dir: dict[str, dict[str, list[dict]]] = {}
    for fp, text in c.all_files_text.items():
        dirkey = str(Path(fp).parent)
        per_dir.setdefault(dirkey, {"count": [], "foreach": []})
        for blk in _corpus_resources(fp, text):
            where = {
                "file": str(fp),
                "line": blk["start_line"],
                "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
            }
            if resource_has_path(blk, "count"):
                per_dir[dirkey]["count"].append(where)
            if resource_has_path(blk, "for_each"):
                per_dir[dirkey]["foreach"].append(where)
    out: list[dict] = []
    for dirkey, buckets in per_dir.items():
        if buckets["count"] and buckets["foreach"]:
            for f in buckets["count"]:
                out.append({"id": c.eid, **f})
    return out


@_register_corpus("prod_no_deletion_protection")
def _corpus_prod_no_deletion_protection(c: CorpusCtx) -> list[dict]:
    """``prod_no_deletion_protection`` — heuristic: resources in a path
    containing "prod" or labelled ``environment = "prod*"``, on a
    protected type, with ``deletion_protection = false`` or absent.
    Honours ``lifecycle.prevent_destroy = true`` as equivalent.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        path_is_prod = "prod" in str(fp).lower()
        for blk in find_blocks(text, RESOURCE_START):
            btype, bname = blk["groups"]
            if btype not in _PROD_PROTECTED_TYPES:
                continue
            body = blk["body"]
            label_prod = bool(re.search(r'environment\s*=\s*"prod', body))
            if not (path_is_prod or label_prod):
                continue
            dp = block_arg_value(body, "deletion_protection")
            prevent_destroy = block_has_nested_path(body, "lifecycle.prevent_destroy")
            if (dp is None or str(dp).lower() == "false") and not prevent_destroy:
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"{btype}.{bname}",
                })
    return out


@_register_corpus("intent_gap")
def _corpus_intent_gap(c: CorpusCtx) -> list[dict]:
    """``intent_gap`` — meta-detector with four ``subkind`` branches
    that compare a declaration's intent (variable name, description
    text, tag) against its enforcement (validation block, deletion
    protection, etc.). Closes the "you said X but didn't enforce X"
    failure class.
    """
    subkind = c.pat.get("subkind", "")
    out: list[dict] = []
    if subkind == "var_name_false_default":
        for fp, ftext in c.all_files_text.items():
            for blk in find_blocks(ftext, VARIABLE_START):
                name = blk["groups"][0]
                desc = block_arg_value(blk["body"], "description") or ""
                if _INTENT_SECURITY_NAME_RE.search(name) or _INTENT_SECURITY_NAME_RE.search(desc):
                    if _INTENT_FALSE_DEFAULT_RE.search(blk["body"]):
                        out.append({
                            "id": c.eid,
                            "file": str(fp),
                            "line": blk["start_line"],
                            "resource": f"variable.{name}",
                        })
    elif subkind == "var_desc_must_no_validation":
        for fp, ftext in c.all_files_text.items():
            for blk in find_blocks(ftext, VARIABLE_START):
                name = blk["groups"][0]
                desc = block_arg_value(blk["body"], "description") or ""
                if _INTENT_MUST_TRUE_RE.search(desc):
                    if not _INTENT_VALIDATION_RE.search(blk["body"]):
                        out.append({
                            "id": c.eid,
                            "file": str(fp),
                            "line": blk["start_line"],
                            "resource": f"variable.{name}",
                        })
    elif subkind == "prod_tag_no_deletion_protection":
        for fp, ftext in c.all_files_text.items():
            for blk in find_blocks(ftext, RESOURCE_START):
                btype, bname = blk["groups"]
                if _INTENT_PROD_TAG_RE.search(blk["body"]):
                    if _INTENT_DEL_PROT_FALSE_RE.search(blk["body"]):
                        out.append({
                            "id": c.eid,
                            "file": str(fp),
                            "line": blk["start_line"],
                            "resource": f"{btype}.{bname}",
                        })
    elif subkind == "prod_tag_force_destroy":
        for fp, ftext in c.all_files_text.items():
            for blk in find_blocks(ftext, RESOURCE_START):
                btype, bname = blk["groups"]
                if _INTENT_PROD_TAG_RE.search(blk["body"]):
                    if _INTENT_FORCE_DESTROY_TRUE_RE.search(blk["body"]):
                        out.append({
                            "id": c.eid,
                            "file": str(fp),
                            "line": blk["start_line"],
                            "resource": f"{btype}.{bname}",
                        })
    return out
