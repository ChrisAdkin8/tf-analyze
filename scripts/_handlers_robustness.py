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

import re
from pathlib import Path

from _hcl import (
    find_blocks,
    block_arg_value,
    block_has_arg,
    brace_walk,
    block_has_nested_path,
)
from detect import (
    InFileCtx,
    CorpusCtx,
    _register_infile,
    _register_corpus,
    RESOURCE_START,
    VARIABLE_START,
    CHECK_START,
    VALIDATION_BLOCK_RE,
    BOOL_COUNT_RE,
    COUNT_GUARD_RE,
    COUNT_ATTR_RE,
    FOREACH_ATTR_RE,
    _COUNT_NAME_RE,
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
        if not VALIDATION_BLOCK_RE.search(blk["body"]):
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
        if not re.search(r'(?m)^\s*assert\s*\{', cblk["body"]):
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
    out: list[dict] = []
    for m in pre_re.finditer(c.text):
        end_after = brace_walk(c.text, m.end() - 1)
        if end_after is None:
            continue
        end = end_after - 1
        body = c.text[m.end():end]
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
    out: list[dict] = []
    for line_no, line_text in enumerate(c.text.splitlines(), 1):
        stripped_line = line_text.lstrip()
        if stripped_line.startswith(("#", "//", "resource ", "module ", "count ")):
            continue
        for m in idx_ref_re.finditer(line_text):
            ref = m.group(1)
            ref_parts = ref.split("[")[0]
            if ref_parts in counted_names:
                if not COUNT_GUARD_RE.search(line_text):
                    out.append({
                        "id": c.eid,
                        "file": str(c.file_path),
                        "line": line_no,
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
    """
    out: list[dict] = []
    for blk in c.resources:
        if not block_has_arg(blk["body"], "count"):
            continue
        btype, bname = blk["groups"]
        body = blk["body"]
        m = _COUNT_NAME_RE.search(body)
        if m:
            preceding = body[:m.start()]
            line_no = blk["start_line"] + preceding.count("\n")
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": line_no,
                "resource": f"{btype}.{bname}",
            })
    return out


@_register_infile("count_bool_pattern")
def _detect_count_bool_pattern(c: InFileCtx) -> list[dict]:
    """``count_bool_pattern`` — detect ``count = <expr> ? 1 : 0`` on
    resources and modules. ROB-COUNTBOOL-001 flags the anti-pattern
    because changing the predicate destroys the resource instead of
    leaving it in place.
    """
    out: list[dict] = []
    for blk in c.resources:
        if BOOL_COUNT_RE.search(blk["body"]):
            btype, bname = blk["groups"]
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    for blk in c.modules:
        if BOOL_COUNT_RE.search(blk["body"]):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"module.{blk['groups'][0]}",
            })
    return out


@_register_infile("ignore_changes_overuse")
def _detect_ignore_changes_overuse(c: InFileCtx) -> list[dict]:
    """``ignore_changes_overuse`` — resources whose
    ``lifecycle.ignore_changes = [...]`` block lists more than
    ``max_attrs`` attributes are likely disabling drift detection by
    attrition rather than declaring a targeted exception. ROB-DRIFT-002
    catches the wildcard ``["*"]`` case; this catches the next failure
    mode at LOW so reviewers see the signal without gating CI.

    Round-30.9 audit fix #20 — the comma-split is quote-aware so a
    value like ``["a,b", "c"]`` correctly counts as two items.
    """
    max_attrs = int(c.pat.get("max_attrs", 5))
    out: list[dict] = []
    for blk in find_blocks(c.text, RESOURCE_START):
        body = blk["body"]
        lc = re.search(r"(?ms)lifecycle\s*\{(.*?)^\s*\}", body)
        if not lc:
            continue
        ic = re.search(r"ignore_changes\s*=\s*\[(.*?)\]", lc.group(1), re.DOTALL)
        if not ic:
            continue
        inner = ic.group(1)
        # ROB-DRIFT-002 owns the wildcard case.
        if re.search(r"['\"]\*['\"]", inner) or "[*]" in inner:
            continue
        items: list[str] = []
        buf: list[str] = []
        in_dq = False
        prev = ""
        for ch in inner:
            if ch == '"' and prev != "\\":
                in_dq = not in_dq
                buf.append(ch)
            elif ch == "," and not in_dq:
                piece = "".join(buf).strip()
                if piece:
                    items.append(piece)
                buf.clear()
            else:
                buf.append(ch)
            prev = ch
        tail = "".join(buf).strip()
        if tail:
            items.append(tail)
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
    upstream changes; toset stabilises.
    """
    list_rhs_re = re.compile(
        r'(?m)^\s*for_each\s*=\s*(\[|tolist\(|toset\s*\(\s*\[)'
    )
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, RESOURCE_START):
            m = list_rhs_re.search(blk["body"])
            if m and m.group(1) != "toset ([":
                if m.group(1).startswith("toset"):
                    continue
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
    on every existing instance. Classic apply-flicker bug.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, RESOURCE_START):
            body = blk["body"]
            leading_ident: str | None = None
            m = _FOREACH_SPLAT_RE.search(body)
            if m:
                leading_ident = m.group(1)
            else:
                m2 = _FOREACH_COMPREHENSION_RE.search(body)
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
    elsewhere are not guarded by length/try/ternary.
    """
    counted: dict[str, int] = {}
    length_count_re = re.compile(r'(?m)^\s*count\s*=\s*length\s*\(')
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, RESOURCE_START):
            if length_count_re.search(blk["body"]):
                key = f"{blk['groups'][0]}.{blk['groups'][1]}"
                counted[key] = blk["start_line"]
    out: list[dict] = []
    if not counted:
        return out
    idx_re = re.compile(r'([\w-]+\.[\w-]+)\[(\d+|count\.index)\]')
    for fp, text in c.all_files_text.items():
        for i, line_text in enumerate(text.splitlines(), 1):
            if "length(" in line_text or "try(" in line_text:
                continue
            if re.search(r'\?\s*', line_text):
                continue
            for m in idx_re.finditer(line_text):
                if m.group(1) in counted:
                    out.append({
                        "id": c.eid,
                        "file": str(fp),
                        "line": i,
                        "resource": m.group(1),
                    })
    return out


@_register_corpus("count_foreach_mix")
def _corpus_count_foreach_mix(c: CorpusCtx) -> list[dict]:
    """``count_foreach_mix`` — per-directory: does any file use ``count``
    AND ``for_each`` on different resources? Anti-pattern that makes
    module consumers deal with both splat and dynamic refs. Flags the
    count users.
    """
    per_dir: dict[str, dict[str, list[dict]]] = {}
    for fp, text in c.all_files_text.items():
        dirkey = str(Path(fp).parent)
        per_dir.setdefault(dirkey, {"count": [], "foreach": []})
        for blk in find_blocks(text, RESOURCE_START):
            if COUNT_ATTR_RE.search(blk["body"]):
                per_dir[dirkey]["count"].append({
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
                })
            if FOREACH_ATTR_RE.search(blk["body"]):
                per_dir[dirkey]["foreach"].append({
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
                })
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
