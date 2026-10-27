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

import ipaddress
import re

from _hcl import (
    find_blocks,
    find_simple_blocks,
    block_arg_value,
    block_has_arg,
    block_has_nested_path,
    resource_has_path,
    resource_values_at,
    mask_comments_and_heredocs,
    brace_walk,
    strip_hcl_context,
)
from _catalog import kubernetes_type_aliases
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


def _name_selected(pat: dict, blk: dict) -> bool:
    """``name_regex`` / ``name_not_regex``: whether the resource's label,
    ``name`` or ``bucket`` matches (resp. none of them matches)."""
    names = (
        blk["groups"][1],
        block_arg_value(blk["body"], "name") or "",
        block_arg_value(blk["body"], "bucket") or "",
    )
    if pat.get("name_regex") and not any(
        re.search(pat["name_regex"], n) for n in names
    ):
        return False
    if pat.get("name_not_regex") and any(
        re.search(pat["name_not_regex"], n) for n in names
    ):
        return False
    return True


def _suppressed_by(spec: dict | None, blk: dict, var_defaults: dict) -> bool:
    """Whether ``suppress_if: {arg, equals | regex}`` holds for a resource:
    a value of `arg` (variables resolved; may be a dotted path such as
    ``default_action.type``, where any instance counts) equals the
    literal, case-insensitively, or matches the regex. Read from the
    parse tree, so `terraform fmt` alignment does not matter."""
    if not spec or not spec.get("arg"):
        return False
    want = str(spec.get("equals", "")).lower().strip("\"'")
    for value in resource_values_at(blk, spec["arg"]):
        actual = str(_resolve_var_ref(value, var_defaults)).strip("\"'")
        if "regex" in spec:
            if re.search(spec["regex"], actual):
                return True
        elif want and actual.lower() == want:
            return True
    return False


def _repo_has(pat: dict, var_defaults: dict) -> bool:
    """``unless_repo_has: T`` — whether a resource of type ``T`` that is
    not ``enabled = false`` exists anywhere in the scan. For account-level
    settings that change what a resource rule means (e.g.
    ``aws_ebs_encryption_by_default`` encrypts every new volume), which
    usually live in another module. The types present are recorded under
    ``__repo_has__`` when the variable contexts are built."""
    rtype = pat.get("unless_repo_has")
    return bool(rtype) and rtype in var_defaults.get("__repo_has__", "").split()


@_register_infile("resource_arg")
def _detect_resource_arg(c: InFileCtx) -> list[dict]:
    """``resource_arg`` — match a regex (or its negation) against the
    value of an argument on every resource of the given type.

    Supports ``regex`` (positive match), ``not_regex`` (negative match),
    ``fire_if_absent`` (fire when the arg is missing entirely), and the
    ``suppress_if`` (see `_suppressed_by`), ``suppress_if_body_contains``
    and ``count = 0`` (resource definitely not created) escape hatches,
    ``name_regex`` / ``name_not_regex`` (see `_name_selected`) and
    ``unless_repo_has`` (see `_repo_has`). Variable references in the value are
    resolved via the directory-scoped var_defaults.

    The value is looked up at ``nested_path`` if set, else at ``arg``;
    either may be dotted (``metadata_options.http_tokens``). Lookups are
    top-level, like ``resource_missing_arg``. Through a repeated block
    the rule fires if **any** instance's value matches, and
    ``fire_if_absent`` fires if any instance lacks it
    (tasks/hcl-parser-migration.md §4.4).
    """
    pat = c.pat
    has_regex = "regex" in pat
    has_not_regex = "not_regex" in pat
    fire_if_absent = pat.get("fire_if_absent", False)
    # `nested_path` alone is enough (it is preferred over `arg` below);
    # requiring `arg` made such patterns silently never fire.
    if "resource" not in pat or not (pat.get("arg") or pat.get("nested_path")):
        return []
    if not has_regex and not has_not_regex:
        return []
    if _repo_has(pat, c.var_defaults):
        return []
    rt = pat["resource"]
    path = pat.get("nested_path") or pat["arg"]
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
        if _suppressed_by(pat.get("suppress_if"), blk, c.var_defaults):
            continue
        if not _name_selected(pat, blk):
            continue
        values = resource_values_at(blk, path)
        if fire_if_absent and (not values or not resource_has_path(blk, path)):
            hit = True
        elif not values:
            continue
        else:
            hit = False
            for val in values:
                val = _resolve_var_ref(val, c.var_defaults)
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


def _has_companion(blk: dict, spec: dict, candidates: list[dict]) -> bool:
    """Whether a resource of type ``spec["resource"]`` among `candidates`
    points at `blk` through its ``spec["via"]`` argument (default
    ``bucket``; a list means any of them): by reference
    (``aws_s3_bucket.x.id``, ``.bucket``, ``[0].id`` …), by the same
    value `blk` has for that argument (``bucket = "my-bucket"``, or the
    same ``local.bucket_name`` / ``var.name`` expression, on both), or by
    iterating it (``for_each = aws_s3_bucket.x`` with
    ``bucket = each.value.id``)."""
    ctype = spec.get("resource")
    via = spec.get("via", "bucket")
    vias = via if isinstance(via, list) else [via]
    if not ctype:
        return False
    btype, bname = blk["groups"]
    ref = re.compile(rf'(?<![\w.]){re.escape(btype)}\.{re.escape(bname)}(?![\w-])')
    literals: dict[str, str] = {}
    for arg in vias:
        literal = block_arg_value(blk["body"], arg)
        # Within one module the same expression is the same value, so
        # `bucket = local.bucket_name` on both links them (it used to be
        # skipped, a false positive). Not `each.` / `count.` / `self.`:
        # those differ per instance.
        if literal and not literal.startswith(("each.", "count.", "self.", "${each.", "${count.")):
            literals[arg] = literal
    for cand in candidates:
        if cand["groups"][0] != ctype:
            continue
        # `for_each = aws_s3_bucket.many` + `bucket = each.value.id`: the
        # companion iterates over this resource's instances.
        for_each = block_arg_value(cand["body"], "for_each") or ""
        iterates_blk = bool(ref.search(for_each))
        for arg in vias:
            value = block_arg_value(cand["body"], arg)
            if value and (ref.search(value) or literals.get(arg) == value):
                return True
            if value and iterates_blk and re.match(r"\$?\{?\s*each\.", value):
                return True
    return False


@_register_infile("ip_range_span")
def _detect_ip_range_span(c: InFileCtx) -> list[dict]:
    """``ip_range_span`` — fire when the IP range a resource allows, from
    ``start_arg`` to ``end_arg``, covers at least ``min_addresses``
    addresses. For firewall rules written as a start / end pair (Azure
    SQL, PostgreSQL / MySQL flexible server, Synapse …): matching the two
    ends against fixed values missed ``0.0.0.1``–``255.255.255.254``,
    which is just as open. Ends that are not literal addresses (an
    unresolved variable) are skipped.
    """
    pat = c.pat
    rt, start_arg, end_arg = pat.get("resource"), pat.get("start_arg"), pat.get("end_arg")
    min_addresses = int(pat.get("min_addresses") or 0)
    if not (rt and start_arg and end_arg and min_addresses):
        return []
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt or _resource_is_count_zero(blk["body"], c.var_defaults):
            continue
        ends = []
        for arg in (start_arg, end_arg):
            values = resource_values_at(blk, arg)
            try:
                ends.append(ipaddress.ip_address(
                    _resolve_var_ref(values[0], c.var_defaults).strip()
                ))
            except (IndexError, ValueError):
                break
        if len(ends) != 2 or ends[0].version != ends[1].version:
            continue
        if int(ends[1]) - int(ends[0]) + 1 >= min_addresses:
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

    Presence is top-level: a same-named key inside a nested block or an
    object attribute (e.g. a ``tags`` key) does not count — rules that
    mean a nested setting use ``nested_path``. When a path segment is a
    repeated block, every instance must have the rest of the path, unless
    the pattern sets ``instances: any`` (tasks/hcl-parser-migration.md
    §4.4). Uses the parse tree when the file parsed, else the regex
    fallback with the same rules.

    Honours ``suppress_if`` (don't fire when a sibling arg equals a value
    or matches a regex; `_suppressed_by`), ``suppress_if_body_contains``, the ``count = 0``
    escape hatch, and the AWS ``default_tags`` propagation (R30.0.12 —
    when the dir's AWS provider declares default_tags, ``tags`` /
    ``tags.*`` paths on aws_* resources are silently provided).

    ``name_regex`` limits the rule to resources whose label, ``name`` or
    ``bucket`` matches; ``name_not_regex`` excludes them. ``unless_companion: {resource: T, via: A}`` skips
    a resource that a ``T`` in the same module points at through its
    ``A`` argument — the split-resource form of a setting, e.g. AWS
    provider v4+'s ``aws_s3_bucket_versioning { bucket =
    aws_s3_bucket.x.id }`` instead of an inline ``versioning`` block.
    """
    pat = c.pat
    if "resource" not in pat:
        return []
    rt = pat["resource"]
    arg_path = pat.get("nested_path") or pat.get("arg") or ""
    if not arg_path:
        return []
    if _repo_has(pat, c.var_defaults):
        return []
    if (
        rt.startswith("aws_")
        and (arg_path == "tags" or arg_path.startswith("tags."))
        and c.var_defaults.get("__aws_default_tags__") == "true"
    ):
        return []
    suppress_if = pat.get("suppress_if")
    suppress_body_contains = pat.get("suppress_if_body_contains")
    companion = pat.get("unless_companion")
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt:
            continue
        if _resource_is_count_zero(blk["body"], c.var_defaults):
            continue
        if suppress_body_contains and suppress_body_contains in blk["body"]:
            continue
        if not _name_selected(pat, blk):
            continue
        if companion and _has_companion(
            blk, companion,
            c.resources if c.module_resources is None else c.module_resources,
        ):
            continue
        # Parse tree when the file parsed, else the regex fallback with
        # the same top-level / every-instance rules (_hcl.resource_has_path).
        present = resource_has_path(
            blk, arg_path, every=pat.get("instances", "all") != "any",
        )
        if not present:
            if _suppressed_by(suppress_if, blk, c.var_defaults):
                continue
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    return out


@_register_infile("resource_missing_companion")
def _detect_resource_missing_companion(c: InFileCtx) -> list[dict]:
    """``resource_missing_companion`` — fire on each ``resource`` that no
    ``companion`` in the same module points at through ``via`` (see
    `_has_companion`): every S3 bucket needs *its own* public access
    block, every VPC its own flow log.

    The per-resource form of ``resource_absent``, which fires only when
    the companion type is missing from the whole repository — so one
    public access block anywhere passed every bucket. Keep
    ``resource_absent`` for account-level singletons (GuardDuty, a
    password policy).

    ``exempt_if_companion: {resource, via}`` exempts a resource that such
    a resource points at — e.g. a bucket that is some
    ``aws_s3_bucket_logging``'s ``target_bucket`` is a log destination and
    does not log its own access.
    """
    pat = c.pat
    rt, ctype, via = pat.get("resource"), pat.get("companion"), pat.get("via")
    if not (rt and ctype and via):
        return []
    spec = {"resource": ctype, "via": via}
    exempt = pat.get("exempt_if_companion")
    candidates = c.resources if c.module_resources is None else c.module_resources
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != rt:
            continue
        if _resource_is_count_zero(blk["body"], c.var_defaults):
            continue
        if _has_companion(blk, spec, candidates):
            continue
        if exempt and _has_companion(blk, exempt, candidates):
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

    Comments and heredoc bodies are blanked before matching, so
    commented-out code and heredoc text (user-data scripts, inline policy
    documents) can't match; ordinary quoted values still can.
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
        if regex.search(mask_comments_and_heredocs(blk["body"])):
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
    must be ``aws:kms``". Honours ``suppress_if_body_contains``. The
    path is walked top-level like ``nested_path`` (parse tree, or the
    regex fallback with the same rules); through a repeated block the
    rule fires if any instance's value differs.
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
        if not_equal is None:
            continue
        ne_norm = str(not_equal).strip().strip('"').strip("'").lower()
        for val in resource_values_at(blk, path):
            val = _resolve_var_ref(val, c.var_defaults)
            v_norm = str(val).strip().strip('"').strip("'").lower()
            if v_norm != ne_norm:
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": blk["start_line"],
                    "resource": f"{btype}.{bname}",
                })
                break
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
    * default — search the full file. ``code_only: true`` first blanks
      comments and heredoc bodies (HCL-aware); ``hcl_context: true``
      blanks comments only (older stripper, keeps heredoc text). Both
      preserve offsets. The match offset is then attributed to a
      resource/data block by position.

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
            # A glob aimed at a `.tf` file also covers its `.tf.json` twin
            # (`**/versions.tf` → `versions.tf.json`).
            matched = c.file_path.match(glob) or (
                glob.endswith(".tf")
                and c.file_path.name.endswith(".tf.json")
                and c.file_path.with_name(c.file_path.name[:-5]).match(glob)
            )
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
    # `code_only: true` blanks comments and heredoc bodies with the
    # HCL-aware lexer (escapes, `${}` nesting, heredocs) — for rules about
    # Terraform structure, which never lives in a comment or heredoc.
    # `hcl_context: true` is the older comment-only stripper; it keeps
    # heredoc text (secret scanning relies on that) but is not
    # heredoc-aware, so a crafted heredoc can confuse its string state.
    if pat.get("code_only"):
        search_text = mask_comments_and_heredocs(c.text)
    elif pat.get("hcl_context"):
        search_text = strip_hcl_context(c.text)
    else:
        search_text = c.text
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
    A ``kubernetes_X`` type also matches ``kubernetes_X_v1`` and back
    (`kubernetes_type_aliases`), for both the target and the prerequisite.
    """
    pat = c.pat
    if "resource" not in pat:
        return []
    rt = pat["resource"]
    targets = kubernetes_type_aliases(rt)
    prerequisite = pat.get("when_present")
    if prerequisite:
        prereqs = kubernetes_type_aliases(prerequisite)
        prereq_seen = False
        for _, text in c.all_files_text.items():
            for blk in find_blocks(text, RESOURCE_START):
                if blk["groups"][0] in prereqs:
                    prereq_seen = True
                    break
            if prereq_seen:
                break
        if not prereq_seen:
            return []
    seen = False
    for _, text in c.all_files_text.items():
        for blk in find_blocks(text, RESOURCE_START):
            if blk["groups"][0] in targets:
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
