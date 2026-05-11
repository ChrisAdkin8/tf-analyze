"""Generic / primitive detector handlers (R30.15).

The 12 catalogue pattern kinds that don't fit a more specific topic.
These are the workhorses — ``grep``, ``resource_arg``,
``resource_missing_arg``, the various "block present / absent"
primitives, and ``deprecated_datasource``. Catalogue rules across
every section (security, robustness, ops, cicd, …) use these as
their basic shape; the topic of the *rule* is encoded by the
catalogue entry, not the handler.

Module load fires the ``@_register_infile`` / ``@_register_corpus``
decorators, populating the dispatch registries in :mod:`detect`. The
file is imported from the bottom of ``detect.py`` after all
module-level state is in place, so the back-imports from ``detect``
resolve cleanly.

Each handler takes an :class:`InFileCtx` or :class:`CorpusCtx` and
returns a list of finding dicts. The handler is the canonical home
of its kind's contract — see each docstring for the catalogue
field interpretation.
"""
from __future__ import annotations

import re

from _hcl import (
    find_blocks,
    find_simple_blocks,
    block_arg_value,
    block_has_arg,
    block_has_nested_path,
    brace_walk,
    strip_hcl_context,
)
from detect import (
    InFileCtx,
    CorpusCtx,
    _register_infile,
    _register_corpus,
    DATA_START,
    RESOURCE_START,
    MOVED_START,
    REMOVED_START,
    _resource_is_count_zero,
    _resolve_var_ref,
)


# ---- In-file handlers ---------------------------------------------------


@_register_infile("resource_present")
def _detect_resource_present(c: InFileCtx) -> list[dict]:
    """``resource_present`` — emit a finding for every resource block
    whose type matches ``pat["resource"]``. Used by catalogue rules
    that flag the mere presence of a forbidden resource type
    (e.g. ``aws_s3_bucket_public_access_block`` defaulting to permissive).
    """
    rt = c.pat.get("resource")
    if not rt:
        return []
    out: list[dict] = []
    for blk in c.resources:
        if blk["groups"][0] == rt:
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
            })
    return out


@_register_infile("data_source_present")
def _detect_data_source_present(c: InFileCtx) -> list[dict]:
    """``data_source_present`` — same shape as ``resource_present`` but
    for ``data "..." "..." { ... }`` blocks. Catalogue rules use this
    to flag data sources that read sensitive material into state
    (e.g. ``data "aws_secretsmanager_secret_version"``).
    """
    dt = c.pat.get("data_source")
    if not dt:
        return []
    out: list[dict] = []
    for blk in find_blocks(c.text, DATA_START):
        if blk["groups"][0] == dt:
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"data.{blk['groups'][0]}.{blk['groups'][1]}",
            })
    return out


@_register_infile("resource_arg")
def _detect_resource_arg(c: InFileCtx) -> list[dict]:
    """``resource_arg`` — match a regex (or its negation) against the
    value of an argument on every resource of the given type.

    Supports ``regex`` (positive match), ``not_regex`` (negative match),
    ``fire_if_absent`` (fire when the arg is missing entirely), and the
    ``suppress_if_body_contains`` and ``count = 0`` (resource definitely
    not created) escape hatches. Variable references in the value are
    resolved via the directory-scoped var_defaults.
    """
    pat = c.pat
    has_regex = "regex" in pat
    has_not_regex = "not_regex" in pat
    fire_if_absent = pat.get("fire_if_absent", False)
    if "resource" not in pat or "arg" not in pat:
        return []
    if not has_regex and not has_not_regex:
        return []
    rt = pat["resource"]
    arg = pat["arg"]
    regex = re.compile(pat["regex"]) if has_regex else None
    not_regex = re.compile(pat["not_regex"]) if has_not_regex else None
    suppress_body_contains = pat.get("suppress_if_body_contains")
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt:
            continue
        if _resource_is_count_zero(blk["body"], c.var_defaults):
            continue
        if suppress_body_contains and suppress_body_contains in blk["body"]:
            continue
        val = block_arg_value(blk["body"], arg)
        if val is None:
            if fire_if_absent:
                hit = True
            else:
                continue
        else:
            val = _resolve_var_ref(val, c.var_defaults)
            hit = False
            if regex and regex.search(val):
                hit = True
            if not_regex and not not_regex.search(val):
                hit = True
        if hit:
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    return out


@_register_infile("resource_missing_arg")
def _detect_resource_missing_arg(c: InFileCtx) -> list[dict]:
    """``resource_missing_arg`` — fire when the named argument (or
    dotted nested path) is absent from a resource body.

    Honours ``suppress_if`` (don't fire when a sibling arg has a
    specific value), ``suppress_if_body_contains``, the ``count = 0``
    escape hatch, and the AWS ``default_tags`` propagation (R30.0.12 —
    when the dir's AWS provider declares default_tags, ``tags`` /
    ``tags.*`` paths on aws_* resources are silently provided).
    """
    pat = c.pat
    if "resource" not in pat:
        return []
    rt = pat["resource"]
    arg_path = pat.get("nested_path") or pat.get("arg") or ""
    if not arg_path:
        return []
    if (
        rt.startswith("aws_")
        and (arg_path == "tags" or arg_path.startswith("tags."))
        and c.var_defaults.get("__aws_default_tags__") == "true"
    ):
        return []
    suppress_if = pat.get("suppress_if")
    suppress_body_contains = pat.get("suppress_if_body_contains")
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt:
            continue
        if _resource_is_count_zero(blk["body"], c.var_defaults):
            continue
        if suppress_body_contains and suppress_body_contains in blk["body"]:
            continue
        if "." in arg_path:
            present = block_has_nested_path(blk["body"], arg_path)
        else:
            present = block_has_arg(blk["body"], arg_path)
        if not present:
            if suppress_if:
                s_arg = suppress_if.get("arg", "")
                s_val = str(suppress_if.get("equals", "")).lower().strip("\"'")
                if s_arg and s_val:
                    actual = block_arg_value(blk["body"], s_arg)
                    if actual:
                        actual = _resolve_var_ref(actual, c.var_defaults)
                    if actual and str(actual).lower().strip("\"'") == s_val:
                        continue
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    return out


@_register_infile("resource_body_contains")
def _detect_resource_body_contains(c: InFileCtx) -> list[dict]:
    """``resource_body_contains`` — fire on every resource of the named
    type whose body matches a regex. Unlike ``grep``, this scopes to a
    specific resource type and respects block boundaries — the regex
    doesn't need to limit itself to ``[^}]``.
    """
    pat = c.pat
    if "resource" not in pat or "regex" not in pat:
        return []
    rt = pat["resource"]
    regex = re.compile(pat["regex"], re.MULTILINE | re.DOTALL)
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt:
            continue
        if regex.search(blk["body"]):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    return out


@_register_infile("hcl_attr")
def _detect_hcl_attr(c: InFileCtx) -> list[dict]:
    """``hcl_attr`` — walk a dotted ``path`` of nested HCL blocks inside
    a resource and compare the leaf value against ``not_equal``.

    Used for rules like "the
    ``server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm``
    must be ``aws:kms``". Honours ``suppress_if_body_contains``. Uses
    the shared ``brace_walk`` (R30.13) to descend through nested
    blocks.
    """
    pat = c.pat
    if "resource" not in pat or "path" not in pat:
        return []
    rt = pat["resource"]
    path = pat["path"]
    not_equal = pat.get("not_equal")
    suppress_body_contains = pat.get("suppress_if_body_contains")
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt:
            continue
        if suppress_body_contains and suppress_body_contains in blk["body"]:
            continue
        parts = path.split(".")
        parent_body = blk["body"]
        for p in parts[:-1]:
            m = re.search(rf'(?m)^\s*{re.escape(p)}\s*\{{', parent_body)
            if not m:
                parent_body = None
                break
            end_after = brace_walk(parent_body, m.end() - 1)
            if end_after is None:
                parent_body = None
                break
            end = end_after - 1
            parent_body = parent_body[m.end():end]
        if parent_body is None:
            continue
        val = block_arg_value(parent_body, parts[-1])
        if val is None:
            continue
        val = _resolve_var_ref(val, c.var_defaults)
        if not_equal is not None:
            v_norm = str(val).strip().strip('"').strip("'").lower()
            ne_norm = str(not_equal).strip().strip('"').strip("'").lower()
            if v_norm != ne_norm:
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": blk["start_line"],
                    "resource": f"{btype}.{bname}",
                })
    return out


@_register_infile("module_block_missing_arg")
def _detect_module_block_missing_arg(c: InFileCtx) -> list[dict]:
    """``module_block_missing_arg`` — fire when a ``module "..." { ... }``
    block whose ``source`` matches ``source_regex`` lacks the named arg.
    """
    pat = c.pat
    if "arg" not in pat:
        return []
    arg = pat["arg"]
    source_re = re.compile(pat.get("source_regex", ".*"))
    out: list[dict] = []
    for blk in c.modules:
        src = block_arg_value(blk["body"], "source") or ""
        if not source_re.search(src):
            continue
        if not block_has_arg(blk["body"], arg):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"module.{blk['groups'][0]}",
            })
    return out


@_register_infile("moved_block_present")
def _detect_moved_block_present(c: InFileCtx) -> list[dict]:
    """``moved_block_present`` — flag every ``moved { ... }`` block.

    Used by rules that warn about stale ``moved`` declarations the
    operator might have forgotten to delete after the state-move
    landed.
    """
    out: list[dict] = []
    for mblk in find_simple_blocks(c.text, MOVED_START):
        out.append({
            "id": c.eid,
            "file": str(c.file_path),
            "line": mblk["start_line"],
            "resource": "moved",
        })
    return out


@_register_infile("removed_block_present")
def _detect_removed_block_present(c: InFileCtx) -> list[dict]:
    """``removed_block_present`` — flag every TF 1.7+ ``removed`` block.

    Same shape as ``moved_block_present``; used to surface stale
    declarations.
    """
    out: list[dict] = []
    for rblk in find_simple_blocks(c.text, REMOVED_START):
        out.append({
            "id": c.eid,
            "file": str(c.file_path),
            "line": rblk["start_line"],
            "resource": "removed",
        })
    return out


@_register_infile("grep")
def _detect_grep(c: InFileCtx) -> list[dict]:
    """``grep`` — the most-used pattern kind. Match a regex against
    file content. Two modes via the ``scope`` field:

    * ``scope == "resource_body"`` — search only inside resource
      bodies, optionally filtered by resource type via ``resource``.
      Honours ``count = 0`` so resources definitely not created are
      skipped.
    * default — search the full file (with comments stripped to
      equal-length whitespace if ``hcl_context: true``). The match
      offset is then attributed to a resource/data block by position.

    The ``not_regex`` field (R30.6) suppresses the rule when the file
    matches a negative pattern — e.g. a workflow file that has both
    ``terraform apply`` and an ``environment:`` block (required-reviewer
    gate) should not fire SEC-CICD-001.

    The ``file_glob`` field (R30.6) restricts the pattern to files
    matching a path-anchored glob (e.g. ``.github/workflows/*.yml``).
    A malformed glob raises loudly (R30.8 audit fix #29).
    """
    pat = c.pat
    if "regex" not in pat:
        return []
    regex = re.compile(pat["regex"], re.MULTILINE)
    not_regex_grep = (
        re.compile(pat["not_regex"], re.MULTILINE)
        if "not_regex" in pat else None
    )
    glob = pat.get("file_glob", "**/*.tf")
    if glob not in ("**/*.tf", "*.tf"):
        try:
            matched = c.file_path.match(glob)
        except ValueError as e:
            raise ValueError(
                f"catalogue rule has malformed file_glob {glob!r}: {e}"
            ) from e
        if not matched:
            return []
    if not_regex_grep is not None and not_regex_grep.search(c.text):
        return []
    scope = pat.get("scope", "")
    out: list[dict] = []
    if scope == "resource_body":
        rt_filter = pat.get("resource", "")
        for blk in c.resources:
            btype, bname = blk["groups"]
            if rt_filter and btype != rt_filter:
                continue
            if _resource_is_count_zero(blk["body"], c.var_defaults):
                continue
            if regex.search(blk["body"]):
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": blk["start_line"],
                    "resource": f"{btype}.{bname}",
                })
        return out
    # Full-file scope. `strip_hcl_context` preserves byte offsets so
    # `m.start()` is valid against `c.text` directly (R30.11 audit fix).
    search_text = strip_hcl_context(c.text) if pat.get("hcl_context") else c.text
    for m in regex.finditer(search_text):
        line = search_text.count("\n", 0, m.start()) + 1
        # Best-effort resource attribution by file position.
        addr = ""
        for blk in c.resources:
            if blk["start_pos"] <= m.start() < blk["end_pos"]:
                addr = f"{blk['groups'][0]}.{blk['groups'][1]}"
                break
        if not addr:
            for dblk in find_blocks(c.text, DATA_START):
                if dblk["start_pos"] <= m.start() < dblk["end_pos"]:
                    addr = f"data.{dblk['groups'][0]}.{dblk['groups'][1]}"
                    break
        out.append({
            "id": c.eid,
            "file": str(c.file_path),
            "line": line,
            "resource": addr,
        })
    return out


# ---- Corpus handlers ----------------------------------------------------


@_register_corpus("resource_absent")
def _corpus_resource_absent(c: CorpusCtx) -> list[dict]:
    """``resource_absent`` — fire once if no resource of the named type
    exists anywhere in the workspace. Used by rules that mandate a
    specific resource type be present (e.g. ``aws_cloudtrail.*``).
    ``when_present`` optionally gates the check on a prerequisite type.
    """
    pat = c.pat
    if "resource" not in pat:
        return []
    rt = pat["resource"]
    prerequisite = pat.get("when_present")
    if prerequisite:
        prereq_seen = False
        for _, text in c.all_files_text.items():
            for blk in find_blocks(text, RESOURCE_START):
                if blk["groups"][0] == prerequisite:
                    prereq_seen = True
                    break
            if prereq_seen:
                break
        if not prereq_seen:
            return []
    seen = False
    for _, text in c.all_files_text.items():
        for blk in find_blocks(text, RESOURCE_START):
            if blk["groups"][0] == rt:
                seen = True
                break
        if seen:
            break
    if seen:
        return []
    return [{
        "id": c.eid,
        "file": str(c.target),
        "line": 0,
        "resource": f"<absent: {rt}>",
    }]


@_register_corpus("deprecated_datasource")
def _corpus_deprecated_datasource(c: CorpusCtx) -> list[dict]:
    """``deprecated_datasource`` — fire on every data source whose type
    is in the ``types`` comma-separated list (default ``template_file``).
    """
    deprecated_types = set((c.pat.get("types") or "").split(",")) or {"template_file"}
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, DATA_START):
            if blk["groups"][0] in deprecated_types:
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"data.{blk['groups'][0]}.{blk['groups'][1]}",
                })
    return out
