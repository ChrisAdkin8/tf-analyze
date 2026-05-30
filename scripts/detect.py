#!/usr/bin/env python3
"""
tf-analyze deterministic detection pass.

Walks every .tf file under <target_dir>, applies every catalogue pattern from
<catalog_dir>, and prints (file, line, catalogue_id) triples on stdout.

Zero external dependencies. The HCL "parser" is regex-based — it handles the
common case (one resource per top-level block, balanced braces) but is
deliberately conservative. False negatives are preferred over false positives.

Usage:
    detect.py --target <dir> [--catalog <dir>] [--format text|json|sarif]
              [--diff-base <ref>] [--auto-stub <dir>]

Output (text):
    SEC-GCP-IAM-001 path/to/file.tf:42 google_project_iam_member.foo
    ROB-GCP-LIFECYCLE-001 path/to/db.tf:17 google_sql_database_instance.main

Output (json):
    [{"id":"SEC-GCP-IAM-001","file":"path/to/file.tf","line":42,
      "resource":"google_project_iam_member.foo"}, ...]

Output (sarif):
    SARIF v2.1.0 JSON for CI annotation (GitHub Actions, Azure DevOps, etc.)

Pattern kinds supported:
    grep                      regex against full file body (set hcl_context: true
                              on the pattern to strip comments before matching)
    resource_arg              resource block whose argument value matches regex
    resource_missing_arg      resource block of type T that lacks arg A
    resource_missing_arg+     same, but arg may be a nested.dotted.path
    resource_present          any resource of type T (urgency comes from default)
    resource_absent           NO resource of type T anywhere in scope (file=*)
    hcl_attr                  resource type T whose attr A is a literal value
    module_block_missing_arg  module block whose source matches regex lacks arg
    variable_type             variable block with `type = <regex>`
    variable_missing_validation  variable block of name regex with no `validation`
    variable_unused           variable declared but never referenced as var.X
    output_unused             output in child module never consumed by callers
    moved_block_present       moved block detected (potential stale cleanup)
    module_missing_tests      module directory with .tf but no .tftest.hcl files
    output_sensitive_leak     output referencing sensitive var without sensitive=true
    cross_module              sensitive var passed to child module input not marked sensitive
    count_index_ref           unguarded [0] reference to count-conditional resource
    count_index_in_name       resource external name embeds count.index (renumber risk)
    count_bool_pattern        count = var.x ? 1 : 0 (should use for_each)
    backend_inconsistency     multiple backend blocks with different types
    templatefile_sensitive_leak  templatefile() call referencing sensitive var
    variable_missing_description  variable block without description argument
    output_missing_description    output block without description argument
    remote_state_present      data "terraform_remote_state" block present
    provider_alias_unused     provider block with alias never referenced
    provider_alias_module_mismatch  module providers={} references undefined alias
    foreach_over_list         for_each where RHS is clearly a list/tuple literal
    count_length_unguarded    count = length(...) with unguarded [0]/[N] references
    count_foreach_mix         same module dir mixes count and for_each resources
    data_external_injection   data.external where program uses var interpolation
    tfstate_in_repo           .tfstate file committed into the scanned directory
    submodule_version_missing submodule directory without required_version
    prod_no_deletion_protection  prod-scoped resource lacks deletion_protection=true
    deprecated_datasource     usage of deprecated data sources (template_file, etc.)
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import json
import fnmatch
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---- Optional python-hcl2 fast-path -------------------------------------
# Moved into `scripts/_hcl.py` in Session F so `_cross_resource.py` and
# any other sibling module can reach `block_arg_value` without
# circular-importing back through `detect`. The toggle (`_USE_HCL2`)
# and detection wrappers are re-imported below alongside the other
# pure HCL primitives.

# Provider/Terraform version-constraint helpers live in
# `scripts/_versions.py`. Re-imported here under the legacy private
# names so existing callers (and the truth-table tests in
# tests/test_a1_improvements.py) continue working without migration.
# Second seam in the modularisation, after `_mitre.py`.
from _versions import (
    _version_tuple,
    _provider_constraint_allows,
    _extract_provider_constraints,
    _extract_terraform_version,
    _entry_applies_to_providers,
)


# HCL primitives + `_USE_HCL2` toggle + `block_arg_value` wrapper all
# live in `scripts/_hcl.py`. Fourth seam in the modularisation; Session
# F (R30.0.12) brought the toggle + `block_arg_value` into `_hcl.py` so
# `_cross_resource.py` could import them cleanly without a circular
# import back through `detect`.
from _hcl import (
    _LINE_COMMENT_RE,
    _BLOCK_COMMENT_RE,
    _DYNAMIC_BLOCK_START_RE,
    _HAS_HCL2,
    _read_normalized,
    _parse_scalar,
    strip_hcl_context,
    find_blocks,
    find_simple_blocks,
    block_has_arg,
    block_arg_value,
    brace_walk,
    _hcl_object_to_json,
    block_has_nested_path,
    _expand_dynamic_blocks,
    _hcl2_block_arg_value,
    _enable_hcl2_or_warn,
    _enable_hcl2_default,
)


# Catalogue lifecycle (YAML loader, schema validation, load_catalog,
# .tf-analyze.yaml workspace config) lives in `scripts/_catalog.py`.
# Fifth seam in the modularisation, after `_mitre.py`, `_versions.py`,
# `_scoring.py`, and `_hcl.py`. Re-imported here so existing callers
# (`from detect import load_yaml`, `validate_catalog_entry`,
# `load_catalog`) keep working without migration.
from _catalog import (
    _VALID_SECTIONS,
    _VALID_URGENCIES,
    _VALID_BLAST_RADIUS,
    _VALID_STATUS,
    _VALID_FIX_DISRUPTIONS,
    _REQUIRED_FIELDS,
    load_yaml,
    validate_catalog_entry,
    _load_project_config,
    load_catalog,
)


# ---- Resource block extraction ------------------------------------------

RESOURCE_START = re.compile(
    r'^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', re.MULTILINE
)
MODULE_START = re.compile(r'^\s*module\s+"([\w-]+)"\s*\{', re.MULTILINE)
VARIABLE_START = re.compile(r'^\s*variable\s+"([\w-]+)"\s*\{', re.MULTILINE)
LOCALS_START = re.compile(r'^\s*locals\s*\{', re.MULTILINE)
MOVED_START = re.compile(r'^\s*moved\s*\{', re.MULTILINE)
IMPORT_START = re.compile(r'^\s*import\s*\{', re.MULTILINE)
REMOVED_START = re.compile(r'^\s*removed\s*\{', re.MULTILINE)
CHECK_START = re.compile(r'^\s*check\s+"([\w-]+)"\s*\{', re.MULTILINE)
OUTPUT_START = re.compile(r'^\s*output\s+"([\w-]+)"\s*\{', re.MULTILINE)
DATA_START = re.compile(
    r'^\s*data\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', re.MULTILINE
)
PROVIDER_START = re.compile(r'^\s*provider\s+"([\w-]+)"\s*\{', re.MULTILINE)

# Hot-path patterns — used inside per-block loops, hoisted out of detector
# branches so they compile once per process, not once per catalog-entry hit.
DESC_RE = re.compile(r'(?m)^\s*description\s*=')
SENSITIVE_TRUE_RE = re.compile(r'(?m)^\s*sensitive\s*=\s*true\s*$')
COUNT_ATTR_RE = re.compile(r'(?m)^\s*count\s*=')
FOREACH_ATTR_RE = re.compile(r'(?m)^\s*for_each\s*=')
VALIDATION_BLOCK_RE = re.compile(r'(?m)^\s*validation\s*\{')
VAR_REF_RE = re.compile(r'\bvar\.([\w-]+)\b')
# Matches when the entire (stripped) attribute value is a plain var.X reference.
_VAR_PLAIN_REF_RE = re.compile(r'^var\.([\w-]+)$')
_LOCAL_PLAIN_REF_RE = re.compile(r'^local\.([\w-]+)$')
# Ternary `<cond> ? <a> : <b>` — only used for constant folding when <cond>
# resolves to a known boolean. Captures cond, then-branch, else-branch.
_TERNARY_RE = re.compile(r'^(.+?)\s*\?\s*(.+?)\s*:\s*(.+)$')
MODULE_REF_RE = re.compile(r'\bmodule\.([\w-]+)\.([\w-]+)')
INLINE_IGNORE_RE = re.compile(r'#\s*tf-analyze:ignore\s+([\w-]+)')
BOOL_COUNT_RE = re.compile(
    r'^\s*count\s*=\s*.*\?\s*1\s*:\s*0\s*$', re.MULTILINE
)
COUNT_GUARD_RE = re.compile(r'\?|try\s*\(|length\s*\(|one\s*\(')


def _path_is_ignored(path: Path, target: Path, ignore_paths: list) -> bool:
    """Return True when ``path`` should be skipped per ``ignore_paths``.

    Each entry is matched against the file's path *relative to the scan
    target* (so users write paths the way they'd type them at the repo
    root). Matching is prefix-style on path components — an entry
    ``examples/`` matches ``examples/foo/main.tf`` and ``examples/bar.tf``
    but never matches ``not-examples/main.tf`` (string-prefix matching
    would).

    Used to honour ``ignore_paths:`` from ``.tf-analyze.yaml`` so a repo
    that ships deliberate negative fixtures (e.g. tf-analyze itself, or
    any security-tool repo with intentionally-vulnerable test corpora)
    can scan only its production code instead of self-scoring against
    the fixtures.
    """
    if not ignore_paths:
        return False
    try:
        rel = path.resolve().relative_to(target.resolve())
    except ValueError:
        return False
    rel_parts = rel.parts
    for raw in ignore_paths:
        pat = str(raw).strip().strip("/").replace("\\", "/")
        if not pat:
            continue
        pat_parts = tuple(pat.split("/"))
        # File matches if every component of the pattern matches the
        # corresponding leading component of the relative path. This is
        # the "prefix on path components" rule documented above — string
        # prefix would let `examples/` accidentally match `examples2/`.
        if len(pat_parts) > len(rel_parts):
            continue
        if rel_parts[:len(pat_parts)] == pat_parts:
            return True
    return False


def _collect_extra_files(
    target: Path,
    entries: list[dict],
    ignore_paths: list | None = None,
) -> list[Path]:
    """Walk `target` for files matching any non-tf `file_glob` declared in
    the catalogue (workflow YAML for SEC-CICD-001..003, tfvars rules, etc.).

    De-duplicates across rules so the same file is read once even when
    multiple catalogue entries share a glob. `.terraform/` is excluded
    so cached provider plugins never appear in the corpus. ``ignore_paths``
    further filters via :func:`_path_is_ignored` so a workflow YAML living
    under an excluded directory (e.g. ``examples/.github/workflows/...``)
    doesn't contaminate the scan.
    """
    _ignore_paths = ignore_paths or []
    extra_globs: set[str] = set()
    for entry in entries:
        for pat in entry.get("patterns", []) or []:
            fg = pat.get("file_glob")
            if not fg or fg in ("**/*.tf", "*.tf"):
                continue
            # The walker handles only the obvious non-tf cases. Specifically
            # leave the tf-shaped globs (which include `*.tf` covered by
            # the main walker) alone here; they're a no-op for this helper.
            if fg.endswith(".tf"):
                continue
            extra_globs.add(fg)

    seen: set[Path] = set()
    out: list[Path] = []
    for glob_pat in sorted(extra_globs):
        # `Path.glob` does not anchor to the root with leading `.`, so
        # `target.glob(".github/workflows/*.yml")` correctly finds files
        # directly under `target/.github/workflows/`. Use `rglob` for
        # `**/...`-style patterns by routing them through `target.glob`,
        # which already supports the `**` wildcard.
        # Round-5 audit fix #15 — narrow the exception handler. The
        # broad `(ValueError, OSError)` previously caught BOTH "the
        # glob pattern was malformed" (a catalogue authorship bug
        # worth surfacing loudly) AND "the directory wasn't readable"
        # (an operator-side issue, also worth surfacing). Split them:
        # ValueError → emit a stderr WARN naming the offending glob;
        # OSError → emit a stderr WARN naming the offending directory.
        # Both still continue (preserving the existing graceful-
        # degradation behaviour) but the operator sees a signal.
        try:
            matches = list(target.glob(glob_pat))
        except ValueError as e:
            sys.stderr.write(
                f"WARN: catalogue glob {glob_pat!r} is malformed ({e}); "
                f"the rule that owns this pattern will never fire.\n"
            )
            continue
        except OSError as e:
            sys.stderr.write(
                f"WARN: cannot list {target} for glob {glob_pat!r} ({e}); "
                f"skipping.\n"
            )
            continue
        for p in matches:
            if ".terraform" in p.parts:
                continue
            if not p.is_file():
                continue
            if _path_is_ignored(p, target, _ignore_paths):
                continue
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            out.append(p)
    return out


def _resolve_var_ref(val: str, var_defaults: dict) -> str:
    """Resolve plain `var.X` / `local.X` references to their known values,
    plus simple ternary constant folding `<bool-ref> ? <a> : <b>`.

    Only substitutes when the entire value is a single reference — compound
    expressions like `var.x == true` are left unchanged.  Data-source
    references (data.X.Y) are intentionally NOT resolved.
    """
    stripped = val.strip()
    m = _VAR_PLAIN_REF_RE.match(stripped)
    if m:
        resolved = var_defaults.get(m.group(1))
        if resolved is not None:
            return resolved
    m = _LOCAL_PLAIN_REF_RE.match(stripped)
    if m:
        resolved = var_defaults.get("__local__" + m.group(1))
        if resolved is not None:
            return resolved
    # Ternary constant folding: `var.x ? "a" : "b"` resolves when var.x has
    # a known boolean default. Other forms left unchanged.
    m = _TERNARY_RE.match(stripped)
    if m:
        cond, then_b, else_b = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        cond_resolved = _resolve_var_ref(cond, var_defaults)
        cond_norm = cond_resolved.strip().strip('"').strip("'").lower()
        if cond_norm == "true":
            return _resolve_var_ref(then_b.strip('"').strip("'"), var_defaults)
        if cond_norm == "false":
            return _resolve_var_ref(else_b.strip('"').strip("'"), var_defaults)
    return val


def _extract_var_defaults_by_dir(all_files_text: dict) -> dict:
    """Return {dir_path: {var_name: default_value}} for all declared variable
    defaults AND locals values, then layer module-call inputs on top.

    Variable scope in Terraform is per-directory.  Locals are stored under
    the key ``__local__<name>`` in the same per-directory dict so that a
    single lookup table can serve both namespaces.

    Module-input flow-through: for every `module "x" { source = "./child"; foo
    = bar }`, push `foo = bar` into the child directory's dict so child-module
    rules see the *caller's* override rather than the child's default.
    """
    result: dict[str, dict[str, str]] = {}
    for fp, text in all_files_text.items():
        dir_key = str(Path(fp).parent)
        for blk in find_blocks(text, VARIABLE_START):
            var_name = blk["groups"][0]
            default = block_arg_value(blk["body"], "default")
            if default is not None:
                result.setdefault(dir_key, {})[var_name] = default
        # Locals blocks: `locals { name = value ... }`  (no groups — use find_blocks
        # variant that returns body only via LOCALS_START which has no capture groups).
        for blk in find_blocks(text, LOCALS_START):
            body = blk["body"]
            # Each line of the body is a `name = value` assignment.
            for lm in re.finditer(r'(?m)^\s*([\w-]+)\s*=\s*(.+?)\s*$', body):
                lname, raw = lm.group(1), lm.group(2)
                # Audit fix #12 — the trailing-comment strip used to be
                # `re.sub(r'\s*#.*$', '', raw)` which is quote-blind: a
                # value like `"value # not a comment"` lost everything
                # from `#` onward. Walk the raw value tracking quote
                # state (matches `_hcl.block_arg_value`'s escape-aware
                # quote walker) and only strip a `#` that lives outside
                # a quoted region.
                in_dq = in_sq = False
                prev = ""
                cut = None
                for idx, ch in enumerate(raw):
                    escaped = prev == "\\"
                    if ch == '"' and not in_sq and not escaped:
                        in_dq = not in_dq
                    elif ch == "'" and not in_dq and not escaped:
                        in_sq = not in_sq
                    elif ch == "#" and not in_dq and not in_sq:
                        cut = idx
                        break
                    prev = ch
                cleaned = raw[:cut].rstrip() if cut is not None else raw.rstrip()
                lval = cleaned.strip().strip('"').strip("'")
                result.setdefault(dir_key, {})["__local__" + lname] = lval

    # AWS provider `default_tags { tags = { ... } }`: any dir whose AWS
    # provider declares default_tags is recorded under the synthetic key
    # __aws_default_tags__. Tag-related findings in that dir are then
    # suppressed (the provider injects the tags downstream).
    PROVIDER_AWS = re.compile(r'^\s*provider\s+"aws"\s*\{', re.MULTILINE)
    for fp, text in all_files_text.items():
        for pm in PROVIDER_AWS.finditer(text):
            # Round-30.13 — shared brace walker. The provider block
            # extraction was previously quote-blind; an aws provider
            # config with a `default_tags { tags = { ... } }` map whose
            # value contained `"k = "v}"`` (rare but possible) would
            # have closed the block prematurely.
            end_after = brace_walk(text, pm.end() - 1)
            if end_after is None:
                continue
            end = end_after - 1  # position of the matching `}` itself
            pbody = text[pm.end():end]
            if "default_tags" in pbody:
                dirk = str(Path(fp).parent)
                result.setdefault(dirk, {})["__aws_default_tags__"] = "true"

    # Module-input flow-through: parent's `module "x" { source = "./c"; k = v }`
    # overrides child dir's `var.k` default. Only literal values flow; var.Y
    # references are resolved against the parent's already-built dict.
    for fp, text in all_files_text.items():
        parent_dir = str(Path(fp).parent)
        parent_vd = result.get(parent_dir, {})
        for mblk in find_blocks(text, MODULE_START):
            source = block_arg_value(mblk["body"], "source")
            if not source or not source.startswith((".", "/")):
                continue
            try:
                child_dir = str((Path(parent_dir) / source).resolve())
            except (OSError, ValueError):
                continue
            for lm in re.finditer(r'(?m)^\s*([\w-]+)\s*=\s*(.+?)\s*$', mblk["body"]):
                k, raw = lm.group(1), lm.group(2)
                # Strip trailing `#` comments before resolution. Otherwise
                # `encrypted = false   # caller note` flows as the literal
                # string `false   # caller note` and downstream rules miss
                # the value match.
                #
                # Round-4 audit fix #7 — the locals branch 60 lines
                # above this site uses a quote-aware comment stripper
                # (R30.10). This sibling path still used the bare
                # `re.sub(r'\s*#.*$', '', raw)` which is quote-blind:
                # `count = "value # not a comment"` lost everything
                # from `#` onward. Mirror the locals walker.
                in_dq = in_sq = False
                prev = ""
                cut = None
                for idx, ch in enumerate(raw):
                    escaped = prev == "\\"
                    if ch == '"' and not in_sq and not escaped:
                        in_dq = not in_dq
                    elif ch == "'" and not in_dq and not escaped:
                        in_sq = not in_sq
                    elif ch == "#" and not in_dq and not in_sq:
                        cut = idx
                        break
                    prev = ch
                v = (raw[:cut] if cut is not None else raw).rstrip()
                if k in ("source", "version", "providers", "count", "for_each",
                         "depends_on", "lifecycle"):
                    continue
                resolved = _resolve_var_ref(v, parent_vd)
                resolved = resolved.strip().strip('"').strip("'")
                # Only flow values that look like literals after resolution;
                # leave child default in place when caller passes an unresolved
                # expression.
                if resolved and not resolved.startswith(("var.", "local.", "data.")):
                    result.setdefault(child_dir, {})[k] = resolved
    return result


def _resource_is_count_zero(body: str, var_defaults: dict) -> bool:
    """Return True if the resource block has `count = 0` (definitely not created).

    Resolves `var.X` and `local.X` references against known defaults.  When
    count is a non-resolvable expression the function returns False (safe default
    — don't skip a resource we can't prove is absent).
    """
    val = block_arg_value(body, "count")
    if val is None:
        return False
    val = _resolve_var_ref(val, var_defaults)
    try:
        return int(val) == 0
    except (ValueError, TypeError):
        return False


# ---- Detection ----------------------------------------------------------

# ---- Detector dispatch (Round 30.14) ------------------------------------
# Two parallel registries replace the 27 + 24 = 51 ``elif kind == "..."``
# branches that previously lived inside ``detect_in_file`` and
# ``detect_corpus``. Each pattern kind now has a dedicated handler that
# takes a ``ctx`` carrying the loop-invariant state, returns the findings
# it produced. The outer function keeps the corpus walks and shared setup
# but the per-kind logic is a registered function — independently
# testable, independently swappable, and far easier to reason about than
# a 700-LoC ``elif`` chain.
#
# Migration is incremental: the dispatch table is consulted FIRST; if no
# handler is registered for a kind, control falls through to the legacy
# elif chain. That lets each branch be migrated one at a time with tests
# passing at every step.

from dataclasses import dataclass
from typing import Callable as _Callable


@dataclass
class InFileCtx:
    """Per-(entry × pat) state for in-file detector handlers.

    Built once per (entry, pat) tuple inside :func:`detect_in_file`'s
    loop, then passed to the handler registered under the pat's
    ``kind`` key. Handlers return their findings; the outer loop
    collects them via ``findings.extend(handler(ctx))``.
    """
    file_path: Path
    text: str
    var_defaults: dict
    resources: list[dict]
    modules: list[dict]
    variables: list[dict]
    entry: dict
    eid: str
    pat: dict


_INFILE_HANDLERS: dict[str, _Callable[["InFileCtx"], list[dict]]] = {}


def _register_infile(kind: str):
    """Register a handler for the given in-file pattern ``kind``.

    Used as a decorator::

        @_register_infile("resource_present")
        def _detect_resource_present(c: InFileCtx) -> list[dict]: ...

    Duplicate registrations raise — the catalogue's ``kind`` values are
    a small, deliberately-curated set, and a typo is worth surfacing
    at module load rather than letting one handler silently shadow
    another.
    """
    def deco(fn):
        if kind in _INFILE_HANDLERS:
            raise RuntimeError(
                f"duplicate in-file handler registration for kind={kind!r}"
            )
        _INFILE_HANDLERS[kind] = fn
        return fn
    return deco


def detect_in_file(
    file_path: Path,
    text: str,
    entries: list[dict],
    var_defaults: dict | None = None,
) -> list[dict]:
    """Run per-file detection patterns against a single .tf file.

    var_defaults: directory-scoped {var_name: default_value} map built by
    _extract_var_defaults_by_dir(). When supplied, plain `var.X` attribute
    values are substituted with their declared defaults before pattern
    matching, reducing false negatives from indirectly-configured attributes.
    """
    _vd: dict = var_defaults or {}
    findings = []
    resources = find_blocks(text, RESOURCE_START)
    # Expand dynamic "X" { content { ... } } blocks within each resource body
    # so that resource_arg / resource_missing_arg / hcl_attr patterns can
    # match attributes that live inside dynamically-generated nested blocks.
    for _blk in resources:
        _blk["body"] = _expand_dynamic_blocks(_blk["body"])
    modules = find_blocks(text, MODULE_START)
    variables = find_blocks(text, VARIABLE_START)

    for entry in entries:
        eid = entry["id"]
        for pat in entry.get("patterns", []) or []:
            kind = pat.get("kind", "")
            # Round 30.14 — registry dispatch. Every in-file detector
            # kind is now a registered handler in `_INFILE_HANDLERS`.
            # Unknown kinds (catalogue-only / corpus-only) fall through
            # silently — `detect_corpus` handles its own kinds; truly
            # malformed catalogue entries are caught at load time by
            # `_catalog.validate_catalog_entry`.
            _handler = _INFILE_HANDLERS.get(kind)
            if _handler is None:
                continue
            _ctx = InFileCtx(
                file_path=file_path,
                text=text,
                var_defaults=_vd,
                resources=resources,
                modules=modules,
                variables=variables,
                entry=entry,
                eid=eid,
                pat=pat,
            )
            findings.extend(_handler(_ctx))
    return findings


# ---- In-file detector handlers (Round 30.14 dispatch table) -------------
# Each handler below was previously an ``elif kind == "..."`` arm inside
# the loop above. Migrating to a registered handler:
#   * Makes each kind independently testable (one handler, one input ctx,
#     one return list of findings).
#   * Removes the implicit dependency on positional order in the elif
#     chain — a registry lookup is order-independent.
#   * Shrinks ``detect_in_file`` itself to the corpus-walk setup +
#     dispatch loop, with the 27+ branches now small functions.
#
# Migration is incremental — the legacy elif chain still handles any
# kind not yet migrated. Each PR can move 1+ kinds at a time with the
# tests passing throughout.


_COUNT_NAME_LIKE_ATTRS = (
    "name", "bucket", "identifier", "hostname",
    "db_name", "instance_name", "cluster_identifier",
    "function_name", "topic_name", "queue_name",
    "table_name", "role_name", "user_name",
    "repository_name", "key_name",
)
_COUNT_NAME_RE = re.compile(
    r'\b(' + "|".join(_COUNT_NAME_LIKE_ATTRS) + r')\s*=\s*'
    r'[^,}\n]*?count\.index[^,}\n]*',
    re.IGNORECASE,
)


def _build_sensitive_var_index(all_files_text: dict) -> dict:
    """Map (file_dir, var_name) -> True if variable is sensitive=true."""
    index = {}
    for fp, text in all_files_text.items():
        dirkey = str(Path(fp).parent)
        for blk in find_blocks(text, VARIABLE_START):
            name = blk["groups"][0]
            if SENSITIVE_TRUE_RE.search(blk["body"]):
                index[(dirkey, name)] = True
    return index


def _build_module_dirs(all_files_text: dict) -> set[str]:
    """Return set of directory paths that contain .tf files (i.e., module dirs)."""
    dirs = set()
    for fp in all_files_text:
        dirs.add(str(Path(fp).parent))
    return dirs


@dataclass
class CorpusCtx:
    """Per-(entry × pat) state for corpus-level detector handlers.

    Built once per (entry, pat) tuple inside :func:`detect_corpus`'s
    loop, then passed to the handler registered under the pat's
    ``kind`` key. Same shape as :class:`InFileCtx` but for the
    workspace-wide passes (cross-module references, unused-output
    detection, backend consistency, etc.).
    """
    target: Path
    all_files_text: dict
    sensitive_vars: dict
    module_dirs: set[str]
    var_refs_by_dir: dict[str, set[str]]
    output_refs: set
    module_sources: dict[str, str]
    # Lazy-built caches the graph_check + registry_fingerprint
    # handlers need. Pre-built once per scan in detect_corpus (the
    # cost is negligible; previously this used a `"X" not in locals()`
    # check inside the elif loop, which doesn't translate cleanly to
    # standalone handler functions).
    resource_index_cache: dict
    module_clusters_cache: dict
    entry: dict
    eid: str
    pat: dict


_CORPUS_HANDLERS: dict[str, _Callable[["CorpusCtx"], list[dict]]] = {}


def _register_corpus(kind: str):
    """Register a handler for the given corpus-level pattern ``kind``."""
    def deco(fn):
        if kind in _CORPUS_HANDLERS:
            raise RuntimeError(
                f"duplicate corpus handler registration for kind={kind!r}"
            )
        _CORPUS_HANDLERS[kind] = fn
        return fn
    return deco


def detect_corpus(target: Path, all_files_text: dict, entries: list) -> list:
    """Patterns that need a global view: resource_absent, output_sensitive_leak,
    cross_module, variable_unused, output_unused, module_missing_tests."""
    findings = []
    sensitive_vars = _build_sensitive_var_index(all_files_text)
    module_dirs = _build_module_dirs(all_files_text)

    # Pre-build per-directory variable reference index for unused detection
    # dir -> set of var names referenced as var.X in any .tf file in that dir
    var_refs_by_dir: dict[str, set[str]] = {}
    for fp, text in all_files_text.items():
        dirkey = str(Path(fp).parent)
        if dirkey not in var_refs_by_dir:
            var_refs_by_dir[dirkey] = set()
        for m in re.finditer(r'\bvar\.([\w-]+)', text):
            var_refs_by_dir[dirkey].add(m.group(1))

    # Pre-build output-consumption index for output_unused:
    # Find all module.X.output_name references across all files
    output_refs: set[tuple[str, str]] = set()  # (module_name, output_name)
    for fp, text in all_files_text.items():
        for m in re.finditer(r'\bmodule\.([\w-]+)\.([\w-]+)', text):
            output_refs.add((m.group(1), m.group(2)))

    # Pre-build module source -> module name mapping for output_unused
    module_sources: dict[str, str] = {}  # module_name -> resolved_child_dir
    for fp, text in all_files_text.items():
        caller_dir = Path(fp).parent
        for mblk in find_blocks(text, MODULE_START):
            mod_name = mblk["groups"][0]
            src = block_arg_value(mblk["body"], "source")
            if src and src.startswith("."):
                child_dir = (caller_dir / src).resolve()
                module_sources[mod_name] = str(child_dir)

    # Round 30.14 — pre-build the lazy caches once. Cheap (sub-ms on
    # multi-thousand-file workspaces) and avoids the per-handler
    # `"X" not in locals()` check the legacy elif chain used.
    _resource_index_cache: dict = _build_resource_index(all_files_text)
    _module_clusters_cache: dict = _build_module_clusters(all_files_text)

    for entry in entries:
        eid = entry["id"]
        for pat in entry.get("patterns", []) or []:
            kind = pat.get("kind", "")
            # Round 30.14 — registry dispatch. Every corpus kind is
            # now registered in `_CORPUS_HANDLERS`. Unknown kinds
            # (in-file kinds or malformed catalogue entries) fall
            # through; catalogue typos are caught at load time by
            # `_catalog.validate_catalog_entry`.
            _handler = _CORPUS_HANDLERS.get(kind)
            if _handler is not None:
                _ctx = CorpusCtx(
                    target=target,
                    all_files_text=all_files_text,
                    sensitive_vars=sensitive_vars,
                    module_dirs=module_dirs,
                    var_refs_by_dir=var_refs_by_dir,
                    output_refs=output_refs,
                    module_sources=module_sources,
                    resource_index_cache=_resource_index_cache,
                    module_clusters_cache=_module_clusters_cache,
                    entry=entry,
                    eid=eid,
                    pat=pat,
                )
                findings.extend(_handler(_ctx))
                continue
    return findings


# ---- Corpus detector handlers (Round 30.14 dispatch table) --------------
# Each handler below was previously an ``elif kind == "..."`` arm inside
# `detect_corpus`. Same migration discipline as `_INFILE_HANDLERS`. Once
# all 26 are registered, the elif chain in detect_corpus is dead code
# (the dispatch hook fires first and continues past it); the legacy chain
# will be removed in a follow-up cleanup commit.


_FOREACH_SAFE_SCOPES = {
    "var", "local", "data", "module", "each", "count",
    "self", "path", "terraform",
}
_FOREACH_SPLAT_RE = re.compile(
    r'(?m)^\s*for_each\s*=\s*(?:toset\s*\(\s*)?([\w-]+)\.([\w-]+)\[\*\]'
)
_FOREACH_COMPREHENSION_RE = re.compile(
    r'(?m)^\s*for_each\s*='
    r'\s*(?:toset\s*\(|tolist\s*\(|setunion\s*\()?'
    r'\s*\{?\s*\[?\s*for\s+[\w,\s]+\s+in\s+([\w-]+)\.([\w-]+)'
)


_PROD_PROTECTED_TYPES = {
    "google_sql_database_instance",
    "google_compute_instance",
    "google_bigquery_dataset",
    "google_container_cluster",
    "google_storage_bucket",
}


# ---- Graph-based checks (cross-resource detection helpers) -------------
# `_build_resource_index` + the 8 `_graph_*` helpers (logging-target,
# GKE node pools, KMS location parity, IAM breadth, Azure UAMI orphan,
# DynamoDB PITR / SSE) — plus the `_GRAPH_CHECKS` registry — live in
# `scripts/_cross_resource.py`. Eighth seam in the modularisation.
# Re-imported here so the `detect_corpus` dispatch + the catalogue's
# `graph_check` kind keep working without migration.
from _cross_resource import (
    _build_resource_index,
    _graph_logging_target_public,
    _graph_gke_nodepool_secure_boot,
    _graph_kms_location_parity,
    _graph_iam_member_breadth,
    _graph_azure_uami_orphan,
    _graph_dynamodb_pitr,
    _graph_dynamodb_sse,
    _GRAPH_CHECKS,
)


# ---- Registry-module fingerprint detector --------------------------------
#
# Detects directories whose resource cluster matches the shape of a popular
# public-registry module (e.g. `terraform-aws-modules/vpc/aws`). Findings
# are advisory (INFO tier) — bespoke implementations are sometimes
# deliberate, so the rule never gates CI by default.
#
# A fingerprint is declared in the catalogue YAML as:
#
#   fingerprint:
#     registry_module: "<namespace>/<module>/<provider>"
#     registry_url:    "<https://...>"
#     min_version:     "~> X.Y"
#     required:                           # all must meet their min count
#       - { type: aws_vpc,    min: 1 }
#     supporting:                         # need ≥ threshold of these types
#       threshold: 3
#       types: [aws_internet_gateway, aws_nat_gateway, ...]
#     exclusions:                         # signal that bespoke is intentional
#       - aws_vpc_ipam_pool

def _build_module_clusters(all_files_text: dict) -> dict:
    """Group resources by parent directory (= one Terraform module).

    Returns ``dir_path_str -> [{type, name, file, line, end_line, lines}, ...]``.
    The fingerprint matcher operates on these clusters; one positive
    match becomes one finding anchored at the directory's first required
    resource. ``lines`` is the resource block's line span (used by the
    ROI estimator to quote a "lines saved" number on the finding).
    """
    clusters: dict[str, list[dict]] = {}
    for fp, text in all_files_text.items():
        d = str(Path(fp).parent)
        for blk in find_blocks(text, RESOURCE_START):
            btype, bname = blk["groups"]
            block_text = blk.get("block_text", "")
            # `start_line` is the resource header; the block ends at the
            # closing `}`. Total lines = newlines spanned + 1 (inclusive).
            line_span = block_text.count("\n") + 1 if block_text else 1
            clusters.setdefault(d, []).append({
                "type": btype,
                "name": bname,
                "file": str(fp),
                "line": blk["start_line"],
                "end_line": blk["start_line"] + max(0, line_span - 1),
                "lines": line_span,
            })
    return clusters


# Typical line count for a registry-module call: provider/version pinning
# + 8-10 input variables + closing brace. The 12-line baseline is the
# anchor against which a cluster's line count is compared to surface
# "you'd save N lines" advisor signal. Conservative: real modules often
# need fewer inputs once registry defaults are accepted.
_MODULE_CALL_BASELINE_LINES = 12


def _module_reuse_roi(resources: list[dict]) -> dict:
    """Estimate lines-saved from replacing a bespoke cluster with a
    registry module call.

    The bespoke total is the sum of every resource block's line span in
    the cluster. The replacement is one module call (~12 lines). The
    delta is what the user would shave by adopting the registry module.

    Returns a dict {bespoke_lines, replacement_lines, lines_saved,
    pct_saved, resource_count} suitable for embedding into the finding.
    """
    bespoke_lines = sum(r.get("lines", 0) for r in resources)
    replacement_lines = _MODULE_CALL_BASELINE_LINES
    lines_saved = max(0, bespoke_lines - replacement_lines)
    pct_saved = (
        round(100 * lines_saved / bespoke_lines)
        if bespoke_lines > 0 else 0
    )
    return {
        "bespoke_lines": bespoke_lines,
        "replacement_lines": replacement_lines,
        "lines_saved": lines_saved,
        "pct_saved": pct_saved,
        "resource_count": len(resources),
    }


def _check_registry_fingerprint(fp: dict, clusters: dict) -> list[dict]:
    """Match every module-cluster against one fingerprint."""
    out: list[dict] = []
    required = fp.get("required") or []
    if not required:
        return out
    supporting = fp.get("supporting") or {}
    sup_types = set(supporting.get("types") or [])
    sup_thresh = int(supporting.get("threshold") or 0)
    excludes = set(fp.get("exclusions") or [])

    for d, resources in clusters.items():
        types_seen = [r["type"] for r in resources]
        type_set = set(types_seen)
        if type_set & excludes:
            continue
        if not all(
            types_seen.count(req["type"]) >= int(req.get("min", 1))
            for req in required
        ):
            continue
        sup_hits = len(type_set & sup_types)
        if sup_hits < sup_thresh:
            continue
        # Confidence scales with overshoot of the supporting threshold so
        # operators can filter or down-weight low-confidence advisories.
        if sup_hits >= sup_thresh + 2:
            confidence = "high"
        elif sup_hits >= sup_thresh + 1:
            confidence = "medium"
        else:
            confidence = "low"

        anchor_type = required[0]["type"]
        anchor = next(r for r in resources if r["type"] == anchor_type)
        roi = _module_reuse_roi(resources)
        # Embed an ROI hint in the context so plain-text consumers
        # (CLI / PR comment) see the savings without needing to look
        # at structured fields. The structured `roi` dict is preserved
        # alongside for the VS Code panel to render explicitly.
        roi_hint = (
            f"; ~{roi['lines_saved']} lines saved "
            f"({roi['pct_saved']}% of {roi['bespoke_lines']} bespoke)"
        ) if roi["lines_saved"] > 0 else ""
        out.append({
            "file": anchor["file"],
            "line": anchor["line"],
            "resource": f"{anchor['type']}.{anchor['name']}",
            "context": (
                f"directory {d} matches {fp.get('registry_module', '?')} "
                f"({sup_hits}/{len(sup_types)} supporting types; "
                f"confidence={confidence}{roi_hint})"
            ),
            "confidence": confidence,
            "registry_url": fp.get("registry_url"),
            "roi": roi,
        })
    return out


# ---- attack graph --------------------------------------------------------
# Attack-graph build + render (constants `_CROWN_JEWEL_TYPES`,
# `_NODE_TYPE_MAP`, the `_INET_*` reachability regexes, the `_EDGE_*`
# cross-resource reference regexes; functions `_is_internet_reachable`,
# `build_attack_graph`, `_score_fix_centrality`,
# `_apply_reachability_urgency`, `_mermaid_id`, `graph_to_mermaid`,
# `_render_graph_html`) lives in `scripts/_attack_graph.py`. Sixth
# seam in the modularisation. Re-imported here so existing callers
# (`tests/test_attack_graph.py`, the HTML report renderer, the
# VS Code extension's `Show Attack Graph` command) keep working.
from _attack_graph import (
    _CROWN_JEWEL_TYPES,
    _NODE_TYPE_MAP,
    _INET_EC2_PUBLIC_IP_RE,
    _INET_RDS_PUBLIC_RE,
    _INET_SQL_PUBLIC_IP_RE,
    _INET_SG_CIDR_RE,
    _INET_SG_IPV6_RE,
    _INET_CLOUDRUN_ALL_RE,
    _INET_ALB_FACING_RE,
    _INET_GCE_ACCESS_CFG_RE,
    _INET_GKE_PRIVATE_RE,
    _INET_AZ_IP_RESTRICTION_RE,
    _EDGE_IAM_PROFILE_RE,
    _EDGE_PROFILE_ROLE_RE,
    _EDGE_KMS_KEY_ID_RE,
    _EDGE_KMS_KEY_NAME_RE,
    _EDGE_KMS_MASTER_RE,
    _EDGE_SECRET_ARN_RE,
    _EDGE_SG_REF_RE,
    _EDGE_GCP_SA_RE,
    _EDGE_GCS_BUCKET_RE,
    _EDGE_AZ_MI_RE,
    _EDGE_AZ_KV_RE,
    _EDGE_AZ_STORAGE_RE,
    _EDGE_AZ_SQL_RE,
    _EDGE_GCP_SA_EMAIL_RE,
    _EDGE_GCP_SA_NAME_RE,
    _is_internet_reachable,
    build_attack_graph,
    _score_fix_centrality,
    _apply_reachability_urgency,
    _mermaid_id,
    graph_to_mermaid,
    _render_graph_html,
)


# ---- intent-gap detection ------------------------------------------------
_INTENT_SECURITY_NAME_RE = re.compile(
    r'(?i)(prod|secure|require|enforce|encrypt|tls|ssl|auth)', re.IGNORECASE
)
_INTENT_FALSE_DEFAULT_RE = re.compile(
    r'(?m)^\s*default\s*=\s*(false|null|0)\s*$'
)
_INTENT_MUST_TRUE_RE = re.compile(
    r'(?i)(must\s+be\s+true|required|enforced|mandatory)', re.IGNORECASE
)
_INTENT_PROD_TAG_RE = re.compile(
    r'(?i)Environment\s*=\s*"?(prod|production)', re.IGNORECASE
)
_INTENT_DEL_PROT_FALSE_RE = re.compile(
    r'(?m)^\s*deletion_protection\s*=\s*false'
)
_INTENT_FORCE_DESTROY_TRUE_RE = re.compile(
    r'(?m)^\s*force_destroy\s*=\s*true'
)
_INTENT_VALIDATION_RE = re.compile(r'\bvalidation\s*\{')


# ---- output formatters --------------------------------------------------
# SARIF, HTML, MITRE, compliance, PR-summary, adversarial-narrative
# rendering, plus the rule-docs canonical URLs they all link to — live
# in `scripts/_output.py`. Seventh seam in the modularisation.
# Re-imported here so existing callers (`--format` dispatch in main(),
# tests/test_output_formats.py, tests/test_pr_summary.py, the GitHub
# Action's pr-summary block, the extension's HTML / SARIF / compliance
# panels) keep working without migration.
from _output import (
    RULE_DOCS_URL_BASE,
    SARIF_HELP_URI_BASE,
    _ATTACK_NARRATIVES,
    _FIX_DISRUPTION_LABELS,
    _sarif_fingerprint,
    _effective_urgency,
    _enrich_findings_for_output,
    _sarif_taxonomies,
    _sarif_rule_relationships,
    to_sarif,
    _narrative_for_finding,
    _render_executive_view,
    _disruption_badge,
    _infer_cis_framework,
    _compliance_gap_report,
    _render_mitre,
    _append_attack_graph_block,
    _render_pr_summary,
    _render_compliance_text,
    _render_compliance_html,
    _compliance_to_oscal,
    _render_fix_priority_html,
    to_html,
)
# MITRE_ATTACK_VERSION + the underscore-prefixed aliases for the
# technique-info table and tactic-order list are re-exported here so
# the legacy `from detect import MITRE_ATTACK_VERSION` path (used by
# the drift gate) and `detect._MITRE_TECHNIQUE_INFO` /
# `detect._MITRE_TACTIC_ORDER` (used by
# tests/test_sarif_taxonomies_and_refactor.py::TestMitreModule) keep
# resolving without migration.
from _mitre import (
    MITRE_ATTACK_VERSION,
    MITRE_TECHNIQUE_INFO as _MITRE_TECHNIQUE_INFO,
    MITRE_TACTIC_ORDER as _MITRE_TACTIC_ORDER,
    mitre_technique_name as _mitre_technique_name,
    mitre_technique_tactics as _mitre_technique_tactics,
)


# verify-fixed mode + auto-stub + tftest gen extracted to
# scripts/_verify.py — 17th seam. The two scanner callbacks are
# injected so _verify.py imports nothing from detect.py.
from _verify import (
    parse_markdown_report,
    reprobe_finding as _verify_reprobe_finding,
    verify_fixed as _verify_verify_fixed,
    write_verification_report,
    generate_stub,
    generate_tftest,
)


def reprobe_finding(finding: dict, catalog_by_id: dict,
                    all_files_text: dict) -> str:
    """Adapter passing detect_in_file + detect_corpus to _verify."""
    return _verify_reprobe_finding(
        finding, catalog_by_id, all_files_text,
        detect_in_file=detect_in_file,
        detect_corpus=detect_corpus,
    )


def verify_fixed(prior_report: Path, target: Path, all_files_text: dict,
                 entries: list[dict]) -> dict:
    """Adapter passing detect_in_file + detect_corpus to _verify."""
    return _verify_verify_fixed(
        prior_report, target, all_files_text, entries,
        detect_in_file=detect_in_file,
        detect_corpus=detect_corpus,
    )


# ---- Diff-mode file filtering -------------------------------------------

# Diff / base-branch helpers extracted to scripts/_diff.py — 11th seam.
from _diff import (
    auto_detect_base_branch as _auto_detect_base_branch,
    find_latest_prior,
    get_diff_files,
)


# Suppression + baseline + comparison helpers extracted to
# scripts/_baseline.py — 15th seam. The inline-suppression regex and
# the YAML loader are injected so _baseline.py stays free of detect.py
# grammar deps.
from _baseline import (
    load_suppressions as _baseline_load_suppressions,
    load_inline_suppressions as _baseline_load_inline_suppressions,
    apply_suppressions,
    apply_baseline,
    compare_reports,
)


def load_suppressions(target: Path) -> tuple[dict, dict]:
    """Public shim — passes detect.py's YAML loader to _baseline."""
    return _baseline_load_suppressions(target, load_yaml=load_yaml)


def load_inline_suppressions(text: str) -> dict[int, set[str]]:
    """Public shim — passes detect.py's INLINE_IGNORE_RE to _baseline."""
    return _baseline_load_inline_suppressions(text, inline_ignore_re=INLINE_IGNORE_RE)


# ---- Catalog loading ----------------------------------------------------

# Risk-score formula + letter-grade helpers + the ordered urgency-tier
# list live in `scripts/_scoring.py`. `_URGENCY_TIERS` was originally
# kept in detect.py as a "not a validation set" carve-out, but Session
# D needed it in `_attack_graph._apply_reachability_urgency`, so it
# moved into `_scoring` alongside `_RISK_WEIGHTS` (the tier-to-points
# map). Re-imported here so existing callers keep working without
# migration. Third seam in the modularisation, after `_mitre.py`
# and `_versions.py`.
from _scoring import (
    _SCORING_VERSION,
    _RISK_WEIGHTS,
    _GRADE_TIERS,
    _URGENCY_TIERS,
    _grade_for_score,
    _compute_summary,
    explain_score,
    render_score_explanation,
)


# ---- Plan-mode rule re-evaluation ----------------------------------------
#
# Static-mode detection runs against the HCL the user wrote, which may
# defer values to apply time (`var.foo`, `${data.X.Y}`). Plan-mode
# re-evaluation walks `terraform show -json plan.tfplan` and re-fires
# the catalogue against the *resolved* values. This catches:
#
#   * variables that resolve to a forbidden value (`role = roles/owner`
#     reached via `var.role` set to `"roles/owner"` in tfvars),
#   * resource attributes computed from data sources or other resources,
#   * count/for_each-expanded resources where rule logic depends on
#     attributes that only exist after expansion.
#
# Only a subset of pattern kinds make sense in plan mode — kinds that
# inspect the literal HCL source (grep, count_index_ref, foreach_*) are
# skipped. Kinds that look at attribute values (resource_arg,
# resource_missing_arg, resource_present, hcl_attr) re-run against
# resolved values.

# Plan / state walker + evaluator extracted to scripts/_plan_state.py
# as the 13th modularisation seam. Public names kept under their old
# private aliases so existing call sites are untouched.
from _plan_state import (
    PLAN_SUPPORTED_KINDS as _PLAN_SUPPORTED_KINDS,
    walk_plan_resources as _walk_plan_resources,
    plan_value_at_path as _plan_value_at_path,
    evaluate_against_resources as _evaluate_against_resources,
    detect_in_plan,
    detect_in_state,
)


# ---- Meta-commands ------------------------------------------------------
#
# `--list-rules`, `--explain`, `--new-rule` operate on the catalogue alone
# and exit without running a scan. They share `load_catalog`, so the same
# schema validation that surfaces broken entries on a real scan also
# surfaces them here — which is the right behaviour: if a rule is
# malformed you want to know before listing it as available.

_RULE_ID_RE = re.compile(r'^[A-Z]+(?:-[A-Z]+)+-\d{3}$')


def _cmd_list_rules(
    catalog_dir: Path,
    focus: str | None,
    include_stubs: bool,
    strict: bool = False,
) -> None:
    """Print every catalogue ID with title + urgency, grouped by domain.

    `strict` forwards `--strict-catalog` into `load_catalog` so any
    YAML parse OR schema-validation error aborts via sys.exit(2)
    instead of being silently logged. The VS Code extension's
    bundle smoke test relies on this — see
    `vscode-extension/scripts/bundle-engine.js`.
    """
    entries = load_catalog(catalog_dir, include_stubs=include_stubs, strict=strict)
    if focus:
        entries = [e for e in entries if e.get("section") == focus]
    if not entries:
        print(
            f"No catalogue entries found"
            + (f" with section={focus}" if focus else "")
            + ".",
            file=sys.stderr,
        )
        return
    by_domain: dict[str, list[dict]] = {}
    for e in entries:
        domain = e["id"].split("-")[0]
        by_domain.setdefault(domain, []).append(e)
    for domain in sorted(by_domain):
        rows = sorted(by_domain[domain], key=lambda x: x["id"])
        print(f"# {domain} ({len(rows)})")
        for e in rows:
            urg = e.get("default_urgency", "?")
            status = e.get("status", "active")
            tag = "" if status == "active" else f" [{status}]"
            print(f"  {e['id']:<32} {urg:<8} {e.get('title', '')}{tag}")
        print()
    print(f"Total: {sum(len(v) for v in by_domain.values())} rule(s).")


def _cmd_explain(catalog_dir: Path, rule_id: str) -> int:
    """Print the full catalogue entry for `rule_id`. Returns exit code."""
    # Round-5 audit fix #2 — validate rule_id against the same regex
    # `_cmd_new_rule` uses (line 2759 below). Without this, `--explain
    # ../../etc/passwd` would resolve to
    # `<catalog_dir>/../../etc/passwd.yaml` — the `.yaml` suffix limits
    # damage to read-only access to .yaml files, but a host that has
    # `/etc/ssh/sshd_config.yaml` or `~/.aws/config.yaml` (uncommon
    # but not unheard of) could be exfiltrated.
    if not _RULE_ID_RE.match(rule_id):
        print(
            f"ERROR: --explain expects a rule ID matching "
            f"{_RULE_ID_RE.pattern!r}; got {rule_id!r}.",
            file=sys.stderr,
        )
        return 2
    yml = catalog_dir / f"{rule_id}.yaml"
    if not yml.exists():
        print(
            f"ERROR: no catalogue entry at {yml}. "
            f"Run --list-rules to see available IDs.",
            file=sys.stderr,
        )
        return 1
    try:
        data = load_yaml(yml.read_text())
    except Exception as e:
        print(f"ERROR: cannot parse {yml}: {e}", file=sys.stderr)
        return 2
    print(f"# {data.get('id', rule_id)} — {data.get('title', '')}")
    print(f"# section: {data.get('section', '?')}")
    print(f"# default_urgency: {data.get('default_urgency', '?')}")
    print(f"# blast_radius: {data.get('blast_radius', '?')}")
    if data.get("status") and data.get("status") != "active":
        print(f"# status: {data['status']}")
    if data.get("cis"):
        print(f"# CIS: {', '.join(str(c) for c in data['cis'])}")
    if data.get("mitre"):
        print(f"# MITRE ATT&CK: {', '.join(str(t) for t in data['mitre'])}")
    if data.get("cwe"):
        print(f"# CWE: {', '.join(str(c) for c in data['cwe'])}")
    if data.get("d3fend"):
        print(f"# MITRE D3FEND: {', '.join(str(d) for d in data['d3fend'])}")
    print()
    print("## Patterns")
    for p in data.get("patterns") or []:
        print(f"  - kind: {p.get('kind', '?')}")
        for k, v in p.items():
            if k != "kind":
                print(f"    {k}: {v}")
    print()
    print("## Recommendation")
    print(data.get("recommendation", "(missing)").rstrip())
    print()
    print("## Verification")
    print(data.get("verification", "(missing)").rstrip())
    if data.get("fixtures"):
        print()
        print(f"## Fixtures: {', '.join(data['fixtures'])}")
    if data.get("related"):
        print(f"## Related: {', '.join(data['related'])}")
    return 0


def _cmd_new_rule(rule_id: str) -> int:
    """Scaffold catalog/<ID>.yaml + fixtures/<slug>/main.tf with TODOs."""
    if not _RULE_ID_RE.match(rule_id):
        print(
            f"ERROR: '{rule_id}' is not a valid rule ID. "
            f"Format: DOMAIN-SUBDOMAIN-NNN (e.g. SEC-IAM-007). "
            f"Domain prefixes: SEC, ROB, DRY, STYLE, SIM, OPS, "
            f"CCD, CI-TEST, MOD, STK, COST, VER.",
            file=sys.stderr,
        )
        return 2
    skill_root = Path(__file__).resolve().parent.parent
    catalog_path = skill_root / "catalog" / f"{rule_id}.yaml"
    if catalog_path.exists():
        print(f"ERROR: {catalog_path} already exists.", file=sys.stderr)
        return 1
    # Derive a fixture slug from the rule id, lower-cased.
    fixture_slug = rule_id.lower().replace("-", "_")
    fixture_dir = skill_root / "fixtures" / fixture_slug
    if fixture_dir.exists():
        print(
            f"ERROR: fixture {fixture_dir} already exists. "
            f"Use a different ID or remove the dir manually.",
            file=sys.stderr,
        )
        return 1
    domain = rule_id.split("-")[0]
    section_guess = {
        "SEC": "security", "ROB": "robustness", "DRY": "dry",
        "STYLE": "style", "SIM": "simplicity", "OPS": "ops",
        "CCD": "cicd", "CI": "cicd", "MOD": "module",
        "STK": "stack", "COST": "ops", "VER": "verification",
    }.get(domain, "robustness")
    catalog_path.write_text(
        f"""id: {rule_id}
title: "TODO: short human title (≤80 chars)"
section: {section_guess}
default_urgency: MEDIUM
blast_radius: single-resource
status: stub
patterns:
  - kind: grep                  # or resource_arg, resource_missing_arg, etc.
    regex: 'TODO: regex'
    description: TODO
recommendation: |
  TODO: describe the fix. Include a code example if helpful.
verification: |
  TODO: describe how to verify the fix landed (gcloud command, terraform plan, etc.).
fixtures:
  - {fixture_slug}
"""
    )
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "main.tf").write_text(
        f"""# Expected findings:
#  - {rule_id} MEDIUM — TODO description

# TODO: write minimal HCL that triggers the rule.
"""
    )
    print(f"# wrote {catalog_path}")
    print(f"# wrote {fixture_dir}/main.tf")
    print()
    print("Next steps:")
    print(f"  1. Edit {catalog_path} — fill TODOs, set status: active when ready.")
    print(f"  2. Edit {fixture_dir}/main.tf — minimal HCL that triggers the rule.")
    print(f"  3. Run scripts/self_test.py — confirm the new fixture passes.")
    print(f"  4. python3 {Path(__file__).name} --explain {rule_id}  # sanity-check the rendered entry")
    return 0


# Fleet + trend modes extracted to scripts/_modes.py — 16th seam.
# Callable-injection (read_normalized, detect_corpus, detect_in_file)
# keeps _modes.py free of any detect.py import — same pattern as
# _lsp.py uses for its `scanner` and `load_catalog` callbacks.
from _modes import (
    resolve_fleet_targets as _resolve_fleet_targets,
    fleet_scan as _fleet_scan_raw,
    render_fleet_report as _render_fleet_report,
    run_trend as _run_trend_raw,
    render_trend_table as _render_trend_table,
)


def _fleet_scan(targets: list[Path], entries: list[dict]) -> dict:
    """detect.py-side adapter passing the heavyweight scan callables."""
    return _fleet_scan_raw(
        targets, entries,
        read_normalized=_read_normalized,
        detect_corpus=detect_corpus,
        detect_in_file=detect_in_file,
    )


def run_trend(target: Path, entries: list[dict], lookback_days: int) -> list[dict]:
    """detect.py-side adapter passing detect_in_file to the trend walker."""
    return _run_trend_raw(
        target, entries, lookback_days,
        detect_in_file=detect_in_file,
    )


# ---- Feature 4: GitHub PR Review Mode ----------------------------------

def _pr_review_mode(args: object, findings: list[dict], entries: list[dict]) -> None:
    """Post findings as GitHub PR inline review comments.

    Requires GITHUB_TOKEN env var and --repo / --pr-number flags.
    Findings with fix_hcl are posted as GitHub suggestion blocks (one-click apply).
    Only findings whose lines appear in the PR diff are posted.
    """
    import urllib.request
    import urllib.error

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("ERROR: GITHUB_TOKEN environment variable is not set", file=sys.stderr)
        sys.exit(2)

    # Audit item 15 — argparse wires `--repo` and `--pr-number`
    # unconditionally, so direct attribute access fails fast on a
    # rename typo instead of silently returning None.
    repo = args.repo
    pr_number = args.pr_number
    if not repo or not pr_number:
        print(
            "ERROR: --repo and --pr-number are required for --mode pr-review",
            file=sys.stderr,
        )
        sys.exit(2)

    entry_map = {e["id"]: e for e in entries}
    api_headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }
    base_url = f"https://api.github.com/repos/{repo}"

    def _gh(url: str, method: str = "GET", payload: dict | None = None) -> dict | list | None:
        data = json.dumps(payload).encode() if payload else None
        req = urllib.request.Request(url, data=data, headers=api_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            print(
                f"ERROR: GitHub API {method} {url}: HTTP {exc.code} — {body[:300]}",
                file=sys.stderr,
            )
            return None

    pr_data = _gh(f"{base_url}/pulls/{pr_number}")
    if not pr_data:
        sys.exit(2)
    head_sha = pr_data["head"]["sha"]  # type: ignore[index]

    pr_files = _gh(f"{base_url}/pulls/{pr_number}/files?per_page=100")
    if not pr_files:
        sys.exit(2)

    # Build {filename: {new_file_line: diff_position}} from unified diffs
    file_positions: dict[str, dict[int, int]] = {}
    for pf in pr_files:  # type: ignore[union-attr]
        fname = pf["filename"]
        patch = pf.get("patch", "")
        if not patch:
            continue
        pos: dict[int, int] = {}
        position = 0
        cur_line = 0
        for dl in patch.splitlines():
            position += 1
            if dl.startswith("@@"):
                m = re.search(r"\+(\d+)", dl)
                if m:
                    cur_line = int(m.group(1)) - 1
            elif dl.startswith("+"):
                cur_line += 1
                pos[cur_line] = position
            elif dl.startswith("\\"):
                # `\ No newline at end of file` — a marker, not a content
                # line. Counting it as context advanced cur_line and shifted
                # every subsequent line→position mapping (comments landed on
                # the wrong line or were dropped).
                continue
            elif not dl.startswith("-"):
                cur_line += 1
                pos[cur_line] = position
        file_positions[fname] = pos

    # Build inline comments. Round-5 audit fix #11 — argparse's
    # `--target` (action="append") guarantees `args.targets` is set
    # (None when no flag passed, list otherwise), so direct attribute
    # access is safe and fails fast on a rename typo.
    targets: list[str] = args.targets or []
    comments: list[dict] = []
    for f in findings:
        entry = entry_map.get(f["id"], {})
        file_path = str(f.get("file", ""))
        line_no = int(f.get("line", 0))
        # Resolve relative path vs repo root
        rel_path = file_path
        for tgt in targets:
            tp = str(Path(tgt).resolve()) + "/"
            abs_fp = str(Path(file_path).resolve())
            if abs_fp.startswith(tp):
                rel_path = abs_fp[len(tp):]
                break
        pos_map = file_positions.get(rel_path, {})
        position = pos_map.get(line_no)
        if position is None:
            continue

        title = entry.get("title", f["id"])
        urgency = _effective_urgency(f, entry)
        recommendation = (entry.get("recommendation") or "").strip()
        body_lines = [
            f"**[tf-analyze] {f['id']}** — {title}",
            f"",
            f"**Urgency:** {urgency}",
            f"",
            recommendation,
        ]
        fix_hcl = (entry.get("fix_hcl") or "").strip()
        if fix_hcl:
            body_lines += ["", "```suggestion", fix_hcl, "```"]
        disruption = entry.get("fix_disruption", "")
        if disruption:
            labels = {
                "none": "Non-disruptive",
                "plan_required": "Requires terraform plan/apply",
                "forces_replacement": "⚠️ Forces resource replacement",
            }
            body_lines.append(f"\n> **Fix disruption:** {labels.get(disruption, disruption)}")

        comments.append({
            "path": rel_path,
            "position": position,
            "body": "\n".join(body_lines),
        })

    if not comments:
        print(
            f"# pr-review: 0 findings map to PR #{pr_number} diff — "
            "ensure --target points to a checkout of the PR branch",
            file=sys.stderr,
        )
        return

    review_payload = {
        "commit_id": head_sha,
        "body": (
            f"tf-analyze found **{len(comments)} finding(s)** in this PR. "
            "See inline comments for details and one-click suggested fixes."
        ),
        "event": "COMMENT",
        "comments": comments,
    }
    result = _gh(f"{base_url}/pulls/{pr_number}/reviews", "POST", review_payload)
    if result:
        print(
            f"# pr-review: posted {len(comments)} comment(s) on PR #{pr_number}",
            file=sys.stderr,
        )
        html_url = (result or {}).get("html_url", "")  # type: ignore[union-attr]
        if html_url:
            print(f"# review URL: {html_url}", file=sys.stderr)
    else:
        sys.exit(2)


# Registry staleness extracted to scripts/_registry.py — 12th seam.
# The injected `MODULE_START` regex keeps _registry.py free of any
# detect.py grammar dependency (only `_hcl` + `_versions`).
from _registry import (
    query_registry_latest as _query_registry_latest,
    check_module_registry_staleness as _check_module_registry_staleness_raw,
)


def _check_module_registry_staleness(all_files_text: dict) -> list[dict]:
    """Thin wrapper passing detect.py's MODULE_START regex to _registry."""
    return _check_module_registry_staleness_raw(all_files_text, MODULE_START)


# ---- Incremental scan cache --------------------------------------------

# Cache helpers extracted to scripts/_cache.py — 10th modularisation seam.
# Names kept as private wrappers so the existing call sites continue to
# work without modification (the bodies are now ten-line shims into the
# new module).
from _cache import (
    corpus_hash as _corpus_hash,
    load_scan_cache as _load_scan_cache,
    save_scan_cache as _save_scan_cache,
)


# ---- Auto-fix helpers ---------------------------------------------------

# Auto-fix helpers extracted to scripts/_apply_fixes.py — 14th seam.
from _apply_fixes import (
    fix_hcl_body as _fix_hcl_body,
    fix_line_for_arg as _fix_line_for_arg,
    fix_block_for_nested_arg as _fix_block_for_nested_arg,
    reindent_fix_snippet as _reindent_fix_snippet,
    find_block_end_in_lines as _find_block_end_in_lines,
    block_indent as _block_indent,
    handle_apply_fixes as _handle_apply_fixes,
)


# ---- Main ---------------------------------------------------------------

def _run_lsp_server(catalog_dir: Path, project_config: dict) -> None:
    """JSON-RPC 2.0 LSP server on stdin/stdout.

    Thin shim around `_lsp.run_lsp_server`. The heavy detection logic
    (`detect_in_file` + `_extract_var_defaults_by_dir`) is wired in here
    via callable injection so `_lsp.py` stays free of `detect` imports
    (R30.7 — ninth modularisation seam).
    """
    from _lsp import run_lsp_server as _lsp_run

    def _scanner(path: Path, entries: list[dict]) -> list[dict]:
        text = path.read_text()
        target_dir = path.parent
        all_files = {
            str(p): p.read_text()
            for p in target_dir.glob("*.tf") if p.exists()
        }
        var_defaults = _extract_var_defaults_by_dir(all_files)
        return detect_in_file(
            path, text, entries, var_defaults.get(str(target_dir), {}),
        )

    _lsp_run(
        catalog_dir, project_config,
        scanner=_scanner,
        load_catalog=load_catalog,
    )


def _default_catalog_dir() -> str:
    """Resolve the default catalogue directory across every layout.

    Order matters:
      1. ``TF_ANALYZE_CATALOG`` env override — explicit wins.
      2. ``<module>/../catalog`` sibling — the source checkout, the bundled
         VS Code engine (``engine/scripts`` + ``engine/catalog``), and the
         Docker image all have this, so their behaviour is unchanged.
      3. The ``tf_analyze_catalog`` data package — only reached on a flat
         ``pip install`` where the sibling doesn't exist; resolves to the
         catalogue YAML shipped as package-data (see ``catalog/__init__.py``).
    """
    env = os.environ.get("TF_ANALYZE_CATALOG")
    if env:
        return env
    sibling = Path(__file__).resolve().parent.parent / "catalog"
    if sibling.is_dir():
        return str(sibling)
    try:
        import tf_analyze_catalog  # type: ignore

        pkg_dir = Path(tf_analyze_catalog.__file__).resolve().parent
        if pkg_dir.is_dir():
            return str(pkg_dir)
    except Exception:
        pass
    return str(sibling)


def _cmd_init(args: object) -> int:
    """Create a project config scaffold (`.tf-analyze.yaml` + an example rule).

    Extracted verbatim from main()'s `--init` branch. Returns an exit code.
    """
    init_target = Path(args.targets[0]).resolve() if args.targets else Path.cwd()
    _cfg_path = init_target / ".tf-analyze.yaml"
    _rules_dir = init_target / ".tf-analyze-rules"
    _rules_dir.mkdir(parents=True, exist_ok=True)
    _cfg_path.write_text(
        "# tf-analyze project configuration\n"
        "# rules_dir: .tf-analyze-rules/\n"
        "# ignore_rules: []\n"
        "# thresholds:\n"
        "#   password_min_length: 14\n"
    )
    (_rules_dir / "CUSTOM-EXAMPLE-001.yaml").write_text(
        "id: CUSTOM-EXAMPLE-001\n"
        'title: "Example: resource missing required Owner tag"\n'
        "section: ops\n"
        "default_urgency: MEDIUM\n"
        "blast_radius: single-resource\n"
        "status: active\n"
        "patterns:\n"
        "  - kind: resource_missing_arg\n"
        "    resource: aws_instance\n"
        "    arg: tags.Owner\n"
        "    description: EC2 instance missing Owner tag required by org policy\n"
        "recommendation: |\n"
        "  Add an Owner tag identifying the team responsible for this resource.\n"
        "      resource \"aws_instance\" \"app\" {\n"
        "        tags = { Owner = \"platform-team\" }\n"
        "      }\n"
        "verification: |\n"
        "  Check that all instances have Owner tag.\n"
        "fix_hcl: |\n"
        "  resource \"aws_instance\" \"app\" {\n"
        "    tags = {\n"
        "      Owner       = \"platform-team\"\n"
        "      Environment = var.environment\n"
        "    }\n"
        "  }\n"
        "fix_disruption: none\n"
        "fixtures: []\n"
    )
    print(f"# created {_cfg_path}", file=sys.stderr)
    print(f"# created {_rules_dir / 'CUSTOM-EXAMPLE-001.yaml'}", file=sys.stderr)
    return 0


def _mode_fleet(args: object, entries: list, emit, out_file) -> int:
    """Scan multiple repos and cross-correlate (`--mode fleet`).

    Extracted verbatim from main(). `emit`/`out_file` are main()'s report-output
    sink and (optional) `--output` file handle. Returns an exit code.
    """
    fleet_targets = _resolve_fleet_targets(args)
    if not fleet_targets:
        print("ERROR: --mode fleet requires at least one --target or --targets-file", file=sys.stderr)
        return 2
    fleet_result = _fleet_scan(fleet_targets, entries)
    total = sum(fleet_result["summary"].values())
    print(f"# fleet: {len(fleet_targets)} repos, {total} total findings, {len(fleet_result['fleet_wide'])} fleet-wide", file=sys.stderr)
    emit(_render_fleet_report(fleet_result, args.format))
    if out_file is not None:
        out_file.close()
    return 0


def _mode_trend(args: object, entries: list, emit, out_file) -> int:
    """Walk git history and compute per-commit finding deltas (`--mode trend`).

    Extracted verbatim from main(). Returns an exit code.
    """
    trend_target = Path(args.targets[0]).resolve() if args.targets else None
    if not trend_target:
        print("ERROR: --mode trend requires --target <git-repo-dir>", file=sys.stderr)
        return 2
    # Round-5 audit fix #11 — argparse defaults `--lookback` to 30
    # so direct attribute access is safe and fails fast on a
    # rename typo (consistent with the other 5 sites converted in
    # R30.8 audit #15).
    lookback = args.lookback
    print(f"# trend: analysing {lookback} days of git history in {trend_target}", file=sys.stderr)
    rows = run_trend(trend_target, entries, lookback)
    print(f"# trend: {len(rows)} commits analysed", file=sys.stderr)
    emit(_render_trend_table(rows, args.format))
    if out_file is not None:
        out_file.close()
    return 0


def _mode_verify_fixed(args: object, entries: list, project_config: dict,
                       target: Path, reports_dir: Path, emit) -> int:
    """Re-probe a prior report's findings and classify fixed/still-present.

    Extracted verbatim from main()'s `--mode verify-fixed` branch. Returns an
    exit code.
    """
    prior = Path(args.prior_report) if args.prior_report else find_latest_prior(reports_dir, ".md")
    if not prior or not prior.exists():
        print(
            f"ERROR: no prior report found (looked in {reports_dir}, "
            f"or --prior-report <path>)",
            file=sys.stderr,
        )
        return 2
    # Load corpus for re-probing
    _ignore_paths_vf = project_config.get("ignore_paths") or []
    tf_files = [
        p for p in target.rglob("*.tf")
        if ".terraform" not in p.parts
        and not _path_is_ignored(p, target, _ignore_paths_vf)
    ]
    all_text = {}
    for fp in tf_files:
        try:
            all_text[fp] = _read_normalized(fp)
        except Exception:
            continue
    verify = verify_fixed(prior, target, all_text, entries)
    if args.format == "json":
        emit(json.dumps(verify, indent=2, default=str))
    else:
        import datetime
        out_path = reports_dir / f"tf-analysis-verify-{datetime.date.today()}.md"
        reports_dir.mkdir(parents=True, exist_ok=True)
        write_verification_report(verify, out_path)
        print(f"# wrote {out_path}")
        for state, rows in verify["results"].items():
            print(f"# {state}: {len(rows)}")
    return 0


def _cmd_apply_fixes(args: object, findings: list, entries: list) -> bool:
    """Apply (or dry-run) `fix_hcl` patches. Returns True if main() should exit.

    Extracted from main(). A real `apply` returns True (main exits so the user
    re-runs to confirm a clean state); a `dry-run` returns False (main falls
    through to normal reporting). `findings` is read-only here — only the
    patcher input is narrowed by `--baseline` / the disruption cap.
    """
    # `--apply-fixes` × `--baseline` (R30.11): when a baseline is set,
    # findings already present in the baseline are not auto-patched.
    # Closes the "snapshot today, fix only new stuff" UX. The full
    # finding list is still emitted in the report; only the patcher
    # input is narrowed.
    fixable_findings = findings
    if args.baseline:
        _baseline_path = Path(args.baseline)
        if _baseline_path.exists():
            _retained, _suppressed_b = apply_baseline(findings, _baseline_path)
            if _suppressed_b:
                print(
                    f"# apply-fixes: skipping {len(_suppressed_b)} baselined finding(s) "
                    f"({len(_retained)} eligible for auto-patch)",
                    file=sys.stderr,
                )
            fixable_findings = _retained

    # R31.2 — disruption-tier cap. Used by the auto-remediation PR bot
    # to limit itself to fixes that don't force replacement. The entry's
    # `fix_disruption` field is the source of truth (`none` <
    # `plan_required` < `forces_replacement`). Default of
    # `forces_replacement` means no cap — backward-compatible.
    _max_disr = getattr(args, "apply_fixes_max_disruption", "forces_replacement")
    if _max_disr != "forces_replacement":
        _disr_rank = {"none": 0, "plan_required": 1, "forces_replacement": 2}
        _cap_rank = _disr_rank[_max_disr]
        _entry_disr = {
            e["id"]: e.get("fix_disruption", "forces_replacement")
            for e in entries
        }
        _before = len(fixable_findings)
        fixable_findings = [
            f for f in fixable_findings
            if _disr_rank.get(_entry_disr.get(f["id"], "forces_replacement"), 2)
            <= _cap_rank
        ]
        _skipped_disr = _before - len(fixable_findings)
        if _skipped_disr:
            print(
                f"# apply-fixes: skipping {_skipped_disr} finding(s) above "
                f"disruption cap '{_max_disr}' "
                f"({len(fixable_findings)} eligible for auto-patch)",
                file=sys.stderr,
            )

    _handle_apply_fixes(
        args, fixable_findings, entries,
        dry_run=(args.apply_fixes == "dry-run"),
    )
    return args.apply_fixes == "apply"


def _cmd_auto_stub(args: object, findings: list, entries: list) -> None:
    """Scaffold catalogue YAML stubs for `--propose-stub` IDs and any finding
    IDs not already in the catalogue.

    Extracted verbatim from main(); read-only over findings/entries and falls
    through (no early exit).
    """
    stub_dir = Path(args.auto_stub)
    stub_dir.mkdir(parents=True, exist_ok=True)
    catalog_ids = {e["id"] for e in entries}
    stub_targets: dict[str, dict] = {}
    if args.propose_stub:
        for pid in [p.strip() for p in args.propose_stub.split(",") if p.strip()]:
            stub_targets[pid] = {"resource": ""}
    for f in findings:
        if f["id"] not in catalog_ids:
            stub_targets.setdefault(f["id"], f)
    stubs_created = []
    for fid, hint in stub_targets.items():
        stub_path = generate_stub(fid, hint, stub_dir)
        if stub_path:
            stubs_created.append(str(stub_path))
    if stubs_created:
        print(f"# auto-stubs created: {len(stubs_created)}", file=sys.stderr)
        for sp in stubs_created:
            print(f"#   {sp}", file=sys.stderr)


def _make_emitter(args: object):
    """Build the report-output sink: returns ``(emit, out_file)``.

    ``emit(text)`` writes a report line to stdout, or to the ``--output`` file
    when one is given; stderr progress lines are unaffected. ``out_file`` is the
    handle (or ``None``) so callers can close it on the happy path.

    Audit follow-up #2 / #15 — the file is closed at the bottom of main() and at
    the early-return sites, but none of those run if a render exception fires
    partway through the ~860-line output block. ``atexit.register`` guarantees a
    close on uncaught exceptions too, without wrapping main() in try/finally. The
    explicit closes are retained (they release the fd sooner on the happy path);
    atexit is the safety net for the exception case.
    """
    out_file = None
    if args.output:
        out_file = open(args.output, "w", encoding="utf-8")
        import atexit
        atexit.register(
            lambda: out_file.close() if (out_file is not None and not out_file.closed) else None
        )

    def emit(text: str) -> None:
        """Write report output to stdout or --output file."""
        if out_file is not None:
            out_file.write(text + "\n")
        else:
            print(text)

    return emit, out_file


def _run_detection(args: object, all_text: dict, extra_text: dict,
                   entries: list, diff_files, target: Path) -> list:
    """Core scan: per-file + corpus detection over the loaded corpus, with the
    incremental cache, plus --plan-json and --state-json (drift) findings merged
    in. Returns the findings list.

    Extracted verbatim from main(). `entries` is the provider-filtered ruleset
    (main() runs that filter first, since downstream consumers reuse the same
    list). stderr-only side effects; no report output.
    """
    # Pass 2 — run per-file detection with the filtered ruleset.
    # Build per-directory variable-default map once; passed into each
    # detect_in_file call so plain `var.X` attribute values are resolved
    # to their declared defaults before pattern matching.
    var_defaults_by_dir = _extract_var_defaults_by_dir(all_text)

    # Incremental cache: if --cache is set and the corpus hash matches the
    # stored cache, return the cached findings immediately (skipping the full
    # scan). The cache covers per-file findings + corpus findings in one shot.
    _cache_path: Path | None = None
    _corpus_hash_val: str | None = None
    _cache_hit = False
    findings: list[dict] = []
    if getattr(args, "cache", False) and diff_files is None:
        # Hash the FULL scanned-file set (.tf + the extra workflow-YAML /
        # tfvars files scanned below), not just .tf. The extra_text scan
        # only runs on a cache MISS, so keying the cache on .tf alone let a
        # warm cache silently skip a secret (or any finding) added to e.g.
        # a `.github/workflows/*.yml` while the .tf files were unchanged.
        _corpus_hash_val = _corpus_hash({**all_text, **extra_text}, entries)
        _cache_path = (
            Path(args.cache_file).resolve()
            if getattr(args, "cache_file", None)
            else target / ".tf-analyze-cache.json"
        )
        _cached = _load_scan_cache(_cache_path)
        if _cached and _cached.get("corpus_hash") == _corpus_hash_val:
            print("# cache hit — skipping full scan", file=sys.stderr)
            findings = _cached.get("findings", [])
            _cache_hit = True

    if not _cache_hit:
        for fp, text in all_text.items():
            if diff_files is not None and fp not in diff_files:
                continue
            findings.extend(
                detect_in_file(fp, text, entries,
                               var_defaults=var_defaults_by_dir.get(str(fp.parent), {}))
            )
        # Run grep-style rules against workflow YAML / tfvars / any
        # other non-tf file_glob (--mode diff intentionally skips these
        # since they are not in the git diff of *.tf files).
        if diff_files is None:
            for fp, text in extra_text.items():
                findings.extend(detect_in_file(fp, text, entries))

    # Plan-mode rule re-evaluation. Findings are merged into the same
    # list so suppression, comparison, and reporting all see them; the
    # `mode` field on each finding lets downstream consumers split.
    if args.plan_json:
        plan_path = Path(args.plan_json).resolve()
        if not plan_path.exists():
            print(
                f"ERROR: --plan-json path does not exist: {plan_path}",
                file=sys.stderr,
            )
            sys.exit(2)
        plan_findings = detect_in_plan(plan_path, entries)
        if plan_findings:
            print(
                f"# {len(plan_findings)} plan-time finding(s) from "
                f"{plan_path.name}",
                file=sys.stderr,
            )
        findings.extend(plan_findings)

    # Drift mode — re-evaluate rules against `terraform show -json
    # state.tfstate` output. R30.12 — closes the gap between HCL intent
    # and actual deployed values for oncalls who need to spot drift
    # without re-running plan.
    # Audit item 15 — argparse wires `--state-json` via dest="state_json"
    # unconditionally; direct access surfaces a rename typo as
    # AttributeError instead of a silent None.
    state_json_arg = args.state_json
    if args.mode == "drift" and not state_json_arg:
        print(
            "ERROR: --mode drift requires --state-json PATH",
            file=sys.stderr,
        )
        sys.exit(2)
    if state_json_arg:
        state_path = Path(state_json_arg).resolve()
        if not state_path.exists():
            print(
                f"ERROR: --state-json path does not exist: {state_path}",
                file=sys.stderr,
            )
            sys.exit(2)
        state_findings = detect_in_state(state_path, entries)
        if state_findings:
            print(
                f"# {len(state_findings)} drift finding(s) from "
                f"{state_path.name}",
                file=sys.stderr,
            )
        findings.extend(state_findings)

    # Corpus-level checks run against all files (even in diff mode)
    if not _cache_hit:
        corpus_findings = detect_corpus(target, all_text, entries)
        if diff_files is not None:
            # Filter corpus findings to only those touching changed files
            corpus_findings = [
                f for f in corpus_findings
                if Path(f["file"]).resolve() in diff_files or f["line"] == 0
            ]
        findings.extend(corpus_findings)

        # Persist to cache after all per-file + corpus findings are collected
        # (before plan / registry findings which require external inputs).
        if _cache_path and _corpus_hash_val:
            _save_scan_cache(_cache_path, _corpus_hash_val, findings)

    return findings


def _render_report(args: object, findings: list, entries: list, *, emit,
                   summary: dict, suppressed_findings: list,
                   suppressed_by_baseline: list, attack_graph, centrality_scores,
                   compliance_report, blast_radius_top, compare_target) -> None:
    """Render findings in the requested ``--format``.

    Handles both the ``--compare`` delta branch and the normal branch. Extracted
    verbatim from main() — a local ``_emit = emit`` alias keeps the moved block
    byte-identical. Writes report output through ``emit``; progress/notices go to
    stderr. No early exit and no file close: main() still owns the ``_out_file``
    lifecycle and the ``--fail-on`` exit code.
    """
    _emit = emit
    # Report comparison
    if compare_target:
        delta = compare_reports(findings, Path(compare_target))
        print(f"# delta: {len(delta['new'])} new, {len(delta['resolved'])} resolved, "
              f"{len(delta['unchanged'])} unchanged", file=sys.stderr)
        if args.format == "json":
            output = {
                "summary": summary,
                "findings": findings,
                "suppressed": suppressed_findings,
                "delta": delta,
            }
            if attack_graph:
                output["graph"] = attack_graph
            if blast_radius_top:
                output["blast_radius"] = blast_radius_top
            if getattr(args, "explain_score", False):
                output["score_explanation"] = explain_score(findings, summary)
            _emit(json.dumps(output, indent=2))
        elif args.format == "sarif":
            sarif = to_sarif(findings, entries)
            _emit(json.dumps(sarif, indent=2))
        elif args.format == "html":
            _emit(to_html(findings, entries, suppressed_findings, graph=attack_graph, show_fixes=getattr(args, "show_fixes", False), centrality=centrality_scores, compliance_data=compliance_report, summary=summary))
        elif args.format == "compliance":
            if compliance_report:
                _emit(_render_compliance_text(compliance_report))
            else:
                _emit(f"# No catalogue entries mapped to compliance framework "
                      f"{getattr(args, 'compliance_framework', 'cis')!r}.")
        elif args.format == "mitre":
            _emit(_render_mitre(findings, entries,
                                tactic_filter=getattr(args, "mitre_tactic", None)))
        elif args.format == "pr-summary":
            _emit(_render_pr_summary(
                findings, entries, summary,
                attack_graph=attack_graph,
                centrality=centrality_scores,
                compliance=compliance_report,
            ))
        else:
            _c = summary["counts"]
            _emit(
                f"# tf-analyze: {summary['score']} ({summary['grade']}) · "
                f"{_c['CRITICAL']} CRITICAL · {_c['HIGH']} HIGH · "
                f"{_c['MEDIUM']} MEDIUM · {_c['LOW']} LOW · {_c['INFO']} INFO"
                + (f" · {summary['suppressed_count']} suppressed"
                   if summary["suppressed_count"] else "")
            )
            if delta["new"]:
                _emit("# NEW findings:")
                for f in delta["new"]:
                    _emit(f"  + {f['id']} {f['file']}:{f['line']} {f['resource']}")
            if delta["resolved"]:
                _emit("# RESOLVED findings:")
                for f in delta["resolved"]:
                    _emit(f"  - {f['id']} {f['file']}:{f['line']} {f['resource']}")
            if delta["unchanged"]:
                _emit(f"# {len(delta['unchanged'])} unchanged finding(s)")
            if attack_graph:
                _emit("\n## Attack Graph\n")
                _emit(graph_to_mermaid(attack_graph))
            if blast_radius_top and getattr(args, "blast_radius", False):
                from _blast_radius import render_blast_radius_text
                _emit("\n" + render_blast_radius_text(blast_radius_top))
            if compliance_report and args.format == "text":
                _emit("\n")
                _emit(_render_compliance_text(compliance_report))
    else:
        # --explain-score (R30.8): rank findings by score contribution
        # so the user sees which fix is worth most. Computed once and
        # threaded into both JSON (`score_explanation` field) and text
        # output (header block before the findings list).
        score_explanation = (
            explain_score(findings, summary)
            if getattr(args, "explain_score", False) else None
        )

        # Standard output
        if args.format == "json":
            output_data: dict = {"summary": summary, "findings": findings}
            if suppressed_findings:
                output_data["suppressed"] = suppressed_findings
            if suppressed_by_baseline:
                output_data["suppressed_by_baseline"] = suppressed_by_baseline
            if attack_graph:
                output_data["graph"] = attack_graph
            if blast_radius_top:
                output_data["blast_radius"] = blast_radius_top
            if score_explanation:
                output_data["score_explanation"] = score_explanation
            _emit(json.dumps(output_data, indent=2))
        elif args.format == "sarif":
            sarif = to_sarif(findings, entries)
            _emit(json.dumps(sarif, indent=2))
        elif args.format == "html":
            _emit(to_html(findings, entries, suppressed_findings, graph=attack_graph, show_fixes=getattr(args, "show_fixes", False), centrality=centrality_scores, compliance_data=compliance_report, summary=summary))
        elif args.format == "compliance":
            if compliance_report:
                _emit(_render_compliance_text(compliance_report))
            else:
                _emit(f"# No catalogue entries mapped to compliance framework "
                      f"{getattr(args, 'compliance_framework', 'cis')!r}.")
        elif args.format == "mitre":
            _emit(_render_mitre(findings, entries,
                                tactic_filter=getattr(args, "mitre_tactic", None)))
        elif args.format == "pr-summary":
            _emit(_render_pr_summary(
                findings, entries, summary,
                attack_graph=attack_graph,
                centrality=centrality_scores,
                compliance=compliance_report,
            ))
        else:
            # Text format: lead with a one-line summary score, then the
            # finding list. The summary always prints (even on a clean
            # repo) so CI logs always carry the headline number.
            _c = summary["counts"]
            _emit(
                f"# tf-analyze: {summary['score']} ({summary['grade']}) · "
                f"{_c['CRITICAL']} CRITICAL · {_c['HIGH']} HIGH · "
                f"{_c['MEDIUM']} MEDIUM · {_c['LOW']} LOW · {_c['INFO']} INFO"
                + (f" · {summary['suppressed_count']} suppressed"
                   if summary["suppressed_count"] else "")
            )
            if score_explanation:
                _emit("")
                _emit(render_score_explanation(score_explanation))
                _emit("")
            entry_map_out = {e["id"]: e for e in entries}
            for f in findings:
                # 🔥 KEV badge: rule's CWE intersects CISA Known Exploited
                # Vulnerabilities (R30.2). Renders before the ID so the
                # visual landmark is at the start of the line.
                kev_badge = "🔥 KEV " if f.get("kev") else ""
                _emit(f"{kev_badge}{f['id']} {f['file']}:{f['line']} {f['resource']}")
                if attack_graph:
                    e_out = entry_map_out.get(f["id"], {})
                    if e_out.get("default_urgency") in ("HIGH", "CRITICAL"):
                        narr = _narrative_for_finding(
                            f["id"], f.get("resource", ""), f.get("file", "")
                        )
                        if narr:
                            _emit(f"  # {narr}")
                if getattr(args, "show_fixes", False):
                    e_out = entry_map_out.get(f["id"], {})
                    if e_out.get("fix_hcl"):
                        disruption = e_out.get("fix_disruption", "")
                        if disruption:
                            _disruption_labels = {
                                "none": "Non-disruptive",
                                "plan_required": "Requires plan/apply",
                                "forces_replacement": "Forces resource replacement",
                            }
                            _emit(f"  # Fix disruption: {_disruption_labels.get(disruption, disruption)}")
                            d_note = e_out.get("fix_disruption_note", "")
                            if d_note:
                                _emit(f"  # {d_note}")
                        for fix_line in e_out["fix_hcl"].strip().splitlines():
                            _emit(f"    {fix_line}")
            if suppressed_findings:
                print(f"# ({len(suppressed_findings)} suppressed)", file=sys.stderr)
            if not findings:
                print("# no findings", file=sys.stderr)
            if attack_graph:
                _emit("\n## Attack Graph\n")
                _emit(graph_to_mermaid(attack_graph))
            if blast_radius_top and getattr(args, "blast_radius", False):
                from _blast_radius import render_blast_radius_text
                _emit("\n" + render_blast_radius_text(blast_radius_top))
            if compliance_report and args.format == "text":
                _emit("\n")
                _emit(_render_compliance_text(compliance_report))


def _add_target_args(ap: argparse.ArgumentParser) -> None:
    """What to scan and which catalogue/config to load."""
    # --target is required for scan modes but not for the meta-commands
    # (--list-rules / --explain / --new-rule). Validation happens after
    # parse so users can `--list-rules` without supplying a target.
    ap.add_argument(
        "--target",
        action="append",
        dest="targets",
        metavar="DIR",
        help="Directory to scan. May be specified multiple times for fleet mode.",
    )
    ap.add_argument(
        "--targets-file",
        default=None,
        metavar="FILE",
        help="File containing one target directory path per line (for --mode fleet).",
    )
    ap.add_argument(
        "--catalog",
        default=_default_catalog_dir(),
        help="Catalog directory",
    )
    ap.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help=(
            "Path to .tf-analyze.yaml project config file. "
            "Default: auto-discover in target directory."
        ),
    )


def _add_catalog_args(ap: argparse.ArgumentParser) -> None:
    """Catalogue meta-commands and rule-selection scoping."""
    # Meta-commands — short-circuit before scan logic. None of these
    # require --target.
    ap.add_argument(
        "--list-rules",
        action="store_true",
        help=(
            "Print every catalogue ID with title and urgency, grouped by "
            "domain. Honors --focus, --include-stubs. No scan is run."
        ),
    )
    ap.add_argument(
        "--explain",
        metavar="RULE-ID",
        default=None,
        help=(
            "Print the full catalogue entry for the given rule ID and "
            "exit. No scan is run."
        ),
    )
    ap.add_argument(
        "--new-rule",
        metavar="RULE-ID",
        default=None,
        help=(
            "Scaffold a new catalogue entry and fixture skeleton for the "
            "given ID (must match DOMAIN-SUBDOMAIN-NNN format). Writes "
            "catalog/<ID>.yaml and fixtures/<slug>/main.tf with TODO "
            "markers, then exits."
        ),
    )
    ap.add_argument(
        "--focus",
        default=None,
        help=(
            "Restrict --list-rules / scans to entries in this section "
            "(security, robustness, dry, style, simplicity, ops, cicd, "
            "module, stack, verification)."
        ),
    )
    ap.add_argument(
        "--strict-catalog",
        action="store_true",
        help=(
            "Abort with exit code 2 on any catalogue schema error. "
            "Default behaviour is loud-warn-and-skip: print ERROR lines "
            "to stderr and continue with the entries that did parse."
        ),
    )
    ap.add_argument(
        "--include-stubs",
        action="store_true",
        help="Include catalogue entries with status: stub",
    )
    ap.add_argument(
        "--only-fixture",
        default=None,
        help="Restrict catalogue to entries listing this fixture name",
    )
    ap.add_argument(
        "--init",
        action="store_true",
        default=False,
        help=(
            "Create .tf-analyze.yaml and .tf-analyze-rules/CUSTOM-EXAMPLE-001.yaml "
            "in the target directory, then exit."
        ),
    )


def _add_output_args(ap: argparse.ArgumentParser) -> None:
    """Output format, destination, and what to include / gate on."""
    ap.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html", "compliance", "mitre", "pr-summary"],
        default="text",
        help=(
            "Output format. `mitre` groups findings by MITRE ATT&CK "
            "technique (using catalogue `mitre:` fields). `pr-summary` "
            "emits a concise GitHub-flavoured Markdown block sized for "
            "PR descriptions / PR-bot summary comments: score banner, "
            "top-3 findings, top fix, attack-graph node count."
        ),
    )
    ap.add_argument(
        "--output",
        metavar="PATH",
        default=None,
        help=(
            "Write report output to PATH instead of stdout. "
            "The file is created or overwritten. stderr (progress, "
            "counts, errors) is unaffected."
        ),
    )
    ap.add_argument(
        "--show-fixes",
        action="store_true",
        default=False,
        help=(
            "When a catalogue entry carries a `fix_hcl` snippet, render it "
            "alongside each finding. HTML: syntax-highlighted block inside "
            "the finding detail. Text: indented snippet below the finding line."
        ),
    )
    ap.add_argument(
        "--show-info",
        action="store_true",
        help=(
            "Include INFO-tier findings (advisory; e.g. module-reuse "
            "suggestions) in output. Default off — INFO findings are "
            "counted in the summary but not rendered."
        ),
    )
    ap.add_argument(
        "--fail-on",
        default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Exit with code 1 if any finding at this urgency or above exists",
    )
    # Suppressions are on by default; --no-suppress is the opt-out toggle.
    # An earlier `--suppress` flag was a confusing no-op (it defaulted to
    # True so passing it changed nothing) and has been removed.
    ap.add_argument(
        "--no-suppress",
        action="store_true",
        help=(
            "Disable all suppression (show every finding). Default: "
            "suppressions from .tf-analyze-ignore.yaml + inline "
            "`# tf-analyze:ignore <ID>` comments are applied."
        ),
    )
    ap.add_argument(
        "--mitre-tactic",
        default=None,
        help=(
            "Restrict --format mitre output to one ATT&CK tactic "
            "(e.g. 'Initial Access', 'Defense Evasion'). "
            "Case-insensitive; hyphens and underscores accepted "
            "as separators ('initial-access' is equivalent)."
        ),
    )


def _add_mode_args(ap: argparse.ArgumentParser) -> None:
    """Execution mode and its per-mode inputs."""
    ap.add_argument(
        "--mode",
        choices=["static", "diff", "verify-fixed", "fleet", "trend", "pr-review", "drift"],
        default="static",
        help=(
            "Execution mode. fleet: multi-repo scan. trend: risk "
            "trajectory over git history. drift (R30.12): re-evaluate "
            "rules against `terraform show -json state.tfstate` output, "
            "catching the gap between the HCL intent and what's actually "
            "deployed. Requires --state-json."
        ),
    )
    ap.add_argument(
        "--diff-base",
        default=None,
        help="Git ref to diff against (e.g., main). Only scan changed .tf files.",
    )
    ap.add_argument(
        "--state-json",
        default=None,
        metavar="PATH",
        help=(
            "Path to `terraform show -json state.tfstate` output. "
            "Required by --mode drift. The catalogue's resource_arg / "
            "resource_missing_arg / resource_present / hcl_attr / "
            "data_source_present kinds are re-evaluated against the "
            "deployed values; findings are tagged mode='state' so "
            "downstream consumers can distinguish drift from "
            "plan-time / static-time triggers of the same rule."
        ),
    )
    ap.add_argument(
        "--plan-json",
        default=None,
        metavar="PATH",
        help=(
            "Path to `terraform show -json plan.tfplan` output. When "
            "supplied, the catalogue's resource_arg / resource_missing_arg "
            "/ resource_present / hcl_attr / data_source_present rules "
            "are re-evaluated against resolved values from the plan. "
            "Static findings still run; plan findings are tagged with "
            "mode='plan' so the report can disambiguate. Required for "
            "catching variable-resolved violations (e.g. tfvars setting "
            "an IAM role to a forbidden value)."
        ),
    )
    ap.add_argument(
        "--lookback",
        type=int,
        default=30,
        metavar="N",
        help="Days of git history to analyse in --mode trend (default: 30).",
    )
    ap.add_argument(
        "--repo",
        default=None,
        metavar="OWNER/REPO",
        help="GitHub repository (owner/repo) for --mode pr-review.",
    )
    ap.add_argument(
        "--pr-number",
        type=int,
        default=None,
        metavar="N",
        help="GitHub pull request number for --mode pr-review.",
    )


def _add_analysis_args(ap: argparse.ArgumentParser) -> None:
    """Optional analyses layered on top of detection (graph, scoring, registry, tests)."""
    ap.add_argument(
        "--attack-graph",
        action="store_true",
        default=False,
        help=(
            "Build a directed attack-path graph from internet-reachable resources to "
            "crown jewels (RDS, KMS keys, Secrets Manager, S3/GCS buckets). "
            "With --format html adds an interactive Attack Graph tab (force-directed SVG, "
            "drag, click-to-inspect, critical path highlighted in red). "
            "With --format text (default) appends a Mermaid flowchart block after findings. "
            "Also enables adversarial scenario narratives for HIGH/CRITICAL findings."
        ),
    )
    ap.add_argument(
        "--blast-radius",
        action="store_true",
        default=False,
        help=(
            "Surface the top-N resources sorted by downstream blast "
            "radius — 'what would a single terraform apply destroy?'. "
            "Implied by --attack-graph; this flag adds a dedicated text "
            "table when --format text. JSON output always carries the "
            "`blast_radius` block when the attack graph is built. "
            "Findings on high-blast-radius resources also carry a "
            "per-finding `blast_radius` integer."
        ),
    )
    ap.add_argument(
        "--explain-score",
        action="store_true",
        default=False,
        help=(
            "Surface the top-5 findings ranked by score contribution, "
            "showing the projected score and grade if each is fixed. "
            "Tells the user which fix is worth most. Renders as a "
            "header block in text / pr-summary output; surfaces as a "
            "structured `score_explanation` object in JSON output."
        ),
    )
    ap.add_argument(
        "--check-registry",
        action="store_true",
        default=False,
        help=(
            "Query the Terraform Registry for the latest version of each "
            "registry-style module source and emit MOD-STALE-001 findings "
            "for modules that are significantly behind (>=1 major or >=3 "
            "minor versions). Requires outbound HTTPS to registry.terraform.io. "
            "Off by default so scans remain offline-capable."
        ),
    )
    ap.add_argument(
        "--gen-tests",
        default=None,
        metavar="OUTDIR",
        help=(
            "Generate .tftest.hcl assertion files for each finding whose "
            "catalogue entry defines a `test_template` field. Files are "
            "written to OUTDIR (created if absent). Native Terraform test "
            "format (requires Terraform >= 1.6)."
        ),
    )


def _add_compliance_args(ap: argparse.ArgumentParser) -> None:
    """Compliance gap reporting and its export formats."""
    ap.add_argument(
        "--compliance",
        action="store_true",
        default=False,
        help=(
            "Add a compliance gap report tab to HTML output, or (with "
            "--format compliance) output a plain-text compliance table. "
            "Use --compliance-framework to choose the standard."
        ),
    )
    ap.add_argument(
        "--compliance-framework",
        default="cis",
        choices=[
            "cis", "pci_dss", "soc2", "owasp_iac",
            # R30.1 — multi-framework taxonomy sweep
            "nist_csf", "nist_800_53", "csa_ccm", "slsa",
            "owasp_top10", "owasp_api", "owasp_cicd",
            "owasp_llm", "owasp_k8s", "owasp_asvs",
            "all",
        ],
        metavar="FRAMEWORK",
        help=(
            "Compliance framework to map against. Choices: "
            "cis (default), pci_dss, soc2, owasp_iac, "
            "nist_csf, nist_800_53, csa_ccm, slsa, "
            "owasp_top10, owasp_api, owasp_cicd, owasp_llm, owasp_k8s, owasp_asvs, "
            "all. 'all' combines every framework in one report. "
            "OWASP sub-modes filter against the namespaced `owasp:` "
            "catalogue field by prefix (e.g. owasp_top10 → items A01..A10). "
            "Requires --compliance or --format compliance."
        ),
    )
    ap.add_argument(
        "--oscal",
        default=None,
        metavar="PATH",
        help=(
            "Write an OSCAL Assessment Results JSON file to PATH. "
            "Requires --compliance. Compatible with any --format."
        ),
    )
    ap.add_argument(
        "--pdf-output",
        default=None,
        metavar="PATH",
        help=(
            "Write a CISO-targetable PDF rendering of the compliance "
            "gap report to PATH. R30.13 — built on top of the HTML "
            "compliance report via weasyprint (optional dep). Pair "
            "with --compliance / --compliance-framework FOO. weasyprint "
            "is not a hard dependency; if not installed, the engine "
            "errors with a one-line install hint and exit 2."
        ),
    )


def _add_threat_intel_args(ap: argparse.ArgumentParser) -> None:
    """CISA KEV / FIRST.org EPSS exploitability ranking."""
    ap.add_argument(
        "--rank-by",
        choices=["urgency", "exploitability", "hybrid"],
        default="urgency",
        help=(
            "Ordering mode for findings (R30.2 — exploitability "
            "prioritisation). `urgency` (default) keeps the legacy "
            "CRITICAL-first ordering. `exploitability` promotes findings "
            "whose rule touches a CWE currently in CISA KEV one urgency "
            "tier and sorts KEV hits first. `hybrid` keeps urgency-first "
            "ordering with the KEV promotion applied. CISA KEV + FIRST.org "
            "EPSS feeds are cached daily at ~/.cache/tf-analyze/. "
            "No comparable OSS IaC scanner integrates KEV today."
        ),
    )
    ap.add_argument(
        "--no-threat-intel",
        action="store_true",
        default=False,
        help=(
            "Disable network fetches for CISA KEV / FIRST.org EPSS. "
            "Falls back to cache if present, otherwise skips KEV / EPSS "
            "enrichment (no badges, no urgency promotion). Useful for "
            "air-gapped CI."
        ),
    )


def _add_comparison_args(ap: argparse.ArgumentParser) -> None:
    """Compare / baseline against a prior report."""
    ap.add_argument(
        "--compare",
        default=None,
        help="Path to a prior JSON report to compare against (outputs delta)",
    )
    ap.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help=(
            "Path to a baseline JSON report. Findings present in the baseline "
            "are suppressed (counted under `suppressed_by_baseline` in JSON "
            "output) so only NEW findings affect the exit code. "
            "Match key: (id, file, line, resource). Use to ratchet a legacy "
            "repo: snapshot today's findings, then enforce no regressions "
            "going forward."
        ),
    )
    ap.add_argument(
        "--prior-report",
        default=None,
        help="Markdown report to verify (for --mode verify-fixed). "
             "If omitted, picks the most recent tf-analysis-*.md under reports/.",
    )
    ap.add_argument(
        "--reports-dir",
        default=None,
        help="Reports directory (default: <skill>/reports). Used for "
             "auto-discovery in --compare and --mode verify-fixed.",
    )
    ap.add_argument(
        "--auto-compare",
        action="store_true",
        help="Auto-discover most recent prior JSON report and compute delta.",
    )


def _add_cache_args(ap: argparse.ArgumentParser) -> None:
    """Incremental scan cache."""
    ap.add_argument(
        "--cache",
        action="store_true",
        default=False,
        help=(
            "Enable incremental scan caching. Stores findings keyed on a "
            "hash of all .tf file contents + catalogue entries in "
            ".tf-analyze-cache.json inside the target directory. "
            "Subsequent runs on unchanged code return the cached findings "
            "instantly. Cache is invalidated automatically when any .tf file "
            "or catalogue rule changes. Use --cache-file to override the path."
        ),
    )
    ap.add_argument(
        "--cache-file",
        default=None,
        metavar="PATH",
        help="Override the cache file path used by --cache (default: <target>/.tf-analyze-cache.json).",
    )


def _add_fix_args(ap: argparse.ArgumentParser) -> None:
    """Auto-remediation (fix_hcl patching) and catalogue-stub scaffolding."""
    ap.add_argument(
        "--apply-fixes",
        default=None,
        choices=["dry-run", "apply"],
        metavar="MODE",
        help=(
            "Auto-apply fix_hcl patches for fixable findings. "
            "'dry-run' prints a unified diff to stdout without writing files. "
            "'apply' writes the patched files to disk (creates .bak backups). "
            "Only resource_missing_arg and resource_arg/hcl_attr patterns are "
            "patched; patterns without fix_hcl are skipped. "
            "Always review dry-run output before applying."
        ),
    )
    ap.add_argument(
        "--apply-fixes-max-disruption",
        default="forces_replacement",
        choices=["none", "plan_required", "forces_replacement"],
        metavar="LEVEL",
        help=(
            "Cap which findings --apply-fixes will touch by their "
            "fix_disruption tier. Default is 'forces_replacement' "
            "(no cap — every fixable finding is applied). 'none' applies "
            "only non-disruptive fixes (the auto-remediation-bot default). "
            "'plan_required' applies non-disruptive plus changes visible in "
            "`terraform plan` but not forcing replacement. Tier ordering: "
            "none < plan_required < forces_replacement."
        ),
    )
    ap.add_argument(
        "--auto-stub",
        default=None,
        help="Directory to write auto-generated catalogue stubs. Combined with "
             "--propose-stub IDs or with findings whose IDs are novel (not in catalog).",
    )
    ap.add_argument(
        "--propose-stub",
        default=None,
        help="Comma-separated list of exploratory IDs to scaffold as stubs. "
             "Used by the judgement pass to promote novel findings. "
             "Requires --auto-stub <dir>.",
    )


def _add_engine_args(ap: argparse.ArgumentParser) -> None:
    """Parser-engine selection (python-hcl2 fast-path vs regex)."""
    ap.add_argument(
        "--use-hcl2",
        action="store_true",
        default=os.environ.get("TF_ANALYZE_USE_HCL2") == "1",
        help=(
            "[deprecated, default-on since v0.2] Enable python-hcl2 "
            "fast-path. Kept for backwards compat; behaviour is now "
            "controlled by --no-hcl2."
        ),
    )
    ap.add_argument(
        "--no-hcl2",
        action="store_true",
        default=os.environ.get("TF_ANALYZE_NO_HCL2") == "1",
        help=(
            "Disable the python-hcl2 fast-path and use the regex parser "
            "exclusively. Useful for benchmarking or when running in a "
            "constrained environment without the optional dependency."
        ),
    )


def _add_lsp_args(ap: argparse.ArgumentParser) -> None:
    """LSP server mode + the transport hints some LSP clients inject."""
    ap.add_argument(
        "--lsp",
        action="store_true",
        default=False,
        help=(
            "Run as a JSON-RPC 2.0 LSP server on stdin/stdout. "
            "Provides real-time diagnostics and code actions for .tf files."
        ),
    )
    # Accepted-but-ignored transport hints injected by some LSP clients
    # (notably vscode-languageclient, which appends `--stdio` to the
    # spawned server's argv when `transport: TransportKind.stdio` is
    # set on the Executable). Without these, argparse rejects the
    # unknown flag with exit code 2 and the LSP startup loop hits the
    # "server crashed 5 times" bailout. We default to stdio anyway, so
    # treating these as no-ops is correct.
    ap.add_argument("--stdio", action="store_true", default=False, help=argparse.SUPPRESS)
    ap.add_argument("--node-ipc", action="store_true", default=False, help=argparse.SUPPRESS)
    ap.add_argument("--socket", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--port", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--clientProcessId", default=None, help=argparse.SUPPRESS)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Delegates to domain-grouped `_add_*_args` helpers so this stays a short
    table of contents instead of ~510 lines of declarations. Every flag, choice,
    default, and help string is unchanged from the original monolith (a
    parser-spec snapshot guards against drift).
    """
    ap = argparse.ArgumentParser()
    _add_target_args(ap)
    _add_catalog_args(ap)
    _add_output_args(ap)
    _add_mode_args(ap)
    _add_analysis_args(ap)
    _add_compliance_args(ap)
    _add_threat_intel_args(ap)
    _add_comparison_args(ap)
    _add_cache_args(ap)
    _add_fix_args(ap)
    _add_engine_args(ap)
    _add_lsp_args(ap)
    return ap


def main():
    ap = _build_parser()
    args = ap.parse_args()
    # python-hcl2 fast-path is on by default; `--no-hcl2` (or
    # TF_ANALYZE_NO_HCL2=1) restores the stdlib-only regex path.  When
    # python-hcl2 isn't installed we silently fall back, but emit a
    # one-line stderr notice the first time so the user knows they're
    # missing the heredoc-aware parser.
    if not args.no_hcl2:
        if _HAS_HCL2:
            _enable_hcl2_default()
        else:
            print(
                "NOTE: python-hcl2 not installed; using regex parser. "
                "`pip install python-hcl2` removes a class of false positives "
                "around heredoc/multi-line attributes. (Pass --no-hcl2 to silence.)",
                file=sys.stderr,
            )

    # Route report output: stdout (default) or a file (--output PATH).
    # See _make_emitter for the atexit safety-net rationale.
    _emit, _out_file = _make_emitter(args)

    catalog_dir = Path(args.catalog).resolve()

    # Normalise targets list (args.targets is None or a list due to action="append")
    if args.targets is None:
        args.targets = []

    # --init: create project config scaffold and exit
    if args.init:
        sys.exit(_cmd_init(args))

    # Load project config from .tf-analyze.yaml
    if args.config:
        _project_config_target = Path(args.config).parent
    elif args.targets:
        _project_config_target = Path(args.targets[0]).resolve()
    else:
        _project_config_target = Path.cwd()
    project_config = _load_project_config(_project_config_target)

    # Resolve extra_rules_dir from project config
    _extra_rules_dir: Path | None = None
    if project_config.get("rules_dir"):
        _extra_rules_dir = _project_config_target / project_config["rules_dir"]

    # Meta-commands run on the catalogue alone — no target needed.
    if args.list_rules:
        _cmd_list_rules(catalog_dir, args.focus, args.include_stubs, strict=args.strict_catalog)
        sys.exit(0)
    if args.explain:
        sys.exit(_cmd_explain(catalog_dir, args.explain))
    if args.new_rule:
        sys.exit(_cmd_new_rule(args.new_rule))

    if not args.targets and args.mode not in ("fleet",) and not args.lsp:
        print(
            "ERROR: --target is required for scan modes. "
            "Use --list-rules / --explain / --new-rule for catalogue ops.",
            file=sys.stderr,
        )
        sys.exit(2)

    entries = load_catalog(
        catalog_dir,
        include_stubs=args.include_stubs,
        strict=args.strict_catalog,
        extra_rules_dir=_extra_rules_dir,
    )
    if not entries:
        print(f"ERROR: no catalogue entries loaded from {catalog_dir}", file=sys.stderr)
        sys.exit(2)

    # LSP server mode — takes over stdin/stdout after catalog is loaded
    if args.lsp:
        _run_lsp_server(catalog_dir, project_config)
        return

    if args.only_fixture:
        name = args.only_fixture
        entries = [
            e for e in entries
            if name in (e.get("fixtures") or [])
        ]
        if not entries:
            print(
                f"ERROR: no catalogue entries reference fixture '{name}'",
                file=sys.stderr,
            )
            sys.exit(2)

    # Fleet mode — scan multiple repos and cross-correlate
    if args.mode == "fleet":
        sys.exit(_mode_fleet(args, entries, _emit, _out_file))

    # Trend mode — walk git history and compute per-commit finding deltas
    if args.mode == "trend":
        sys.exit(_mode_trend(args, entries, _emit, _out_file))

    target = Path(args.targets[0]).resolve()

    # Reports directory — used for auto-compare and verify-fixed discovery
    reports_dir = (
        Path(args.reports_dir)
        if args.reports_dir
        else Path(__file__).parent.parent / "reports"
    )

    # verify-fixed mode — early exit with dedicated output
    if args.mode == "verify-fixed":
        sys.exit(_mode_verify_fixed(args, entries, project_config, target, reports_dir, _emit))

    # Determine file set
    diff_files = None
    if args.diff_base or args.mode == "diff":
        base = args.diff_base or _auto_detect_base_branch(target)
        diff_files = get_diff_files(target, base)
        if not diff_files:
            print("# no changed .tf files in diff", file=sys.stderr)

    # Load suppressions. expired_suppressions is shown in the report so
    # findings that just lost their cover are visible as "expired
    # suppression" rather than buried under "new findings".
    global_suppressions: dict = {}
    expired_suppressions: dict = {}
    if not args.no_suppress:
        global_suppressions, expired_suppressions = load_suppressions(target)
        if expired_suppressions:
            print(
                f"# {len(expired_suppressions)} suppression(s) expired; "
                f"affected findings will be tagged in the report",
                file=sys.stderr,
            )

    _ignore_paths = project_config.get("ignore_paths") or []
    tf_files = [
        p for p in target.rglob("*.tf")
        if ".terraform" not in p.parts
        and not _path_is_ignored(p, target, _ignore_paths)
    ]
    if _ignore_paths:
        print(
            f"# ignore_paths active: skipping {', '.join(map(str, _ignore_paths))}",
            file=sys.stderr,
        )
    # Workflow-YAML walker — pick up `.github/workflows/*.yml`, `*.tfvars`,
    # and any other non-tf file_glob declared in the catalogue so the
    # CICD rules (SEC-CICD-001/002/003) actually fire. The Terraform
    # rules still filter by `file_path.match(file_glob)` inside
    # `detect_in_file`, so adding workflow YAMLs to the corpus does not
    # cross-contaminate tf rules.
    extra_files = _collect_extra_files(target, entries, ignore_paths=_ignore_paths)

    # Pass 1 — load every file so we can compute provider constraints
    # before deciding which rules apply. Inline suppressions are also
    # collected here so we don't have to re-read text in pass 2.
    all_text = {}
    file_inline_suppressions: dict[str, dict[int, set[str]]] = {}
    for fp in tf_files:
        try:
            text = _read_normalized(fp)
        except Exception as e:
            print(f"WARN: cannot read {fp}: {e}", file=sys.stderr)
            continue
        all_text[fp] = text
        if not args.no_suppress:
            file_inline_suppressions[str(fp)] = load_inline_suppressions(text)

    # Extra files (workflow YAML, tfvars, etc.) — read with the same
    # normaliser, but never used for provider-constraint detection.
    extra_text: dict = {}
    for fp in extra_files:
        try:
            extra_text[fp] = _read_normalized(fp)
        except Exception as e:
            print(f"WARN: cannot read {fp}: {e}", file=sys.stderr)

    # Provider/Terraform-version-aware filter: entries with `applies_when`
    # are skipped when the target's required_providers / required_version
    # constraint cannot reach the minimum version. Surface the skip count
    # so users know rules are conditionally off rather than silently
    # disabled.
    provider_constraints = _extract_provider_constraints(all_text)
    tf_constraint = _extract_terraform_version(all_text)
    pre_filter = len(entries)
    entries = [
        e for e in entries
        if _entry_applies_to_providers(e, provider_constraints, tf_constraint)
    ]
    skipped = pre_filter - len(entries)
    if skipped:
        print(
            f"# {skipped} rule(s) skipped due to applies_when "
            f"provider/terraform-version constraints",
            file=sys.stderr,
        )

    # Pass 2 — per-file + corpus detection (with the incremental cache),
    # plus --plan-json and --state-json (drift) findings merged in.
    # See _run_detection. `entries` is already provider-filtered above.
    findings = _run_detection(args, all_text, extra_text, entries, diff_files, target)

    # Registry staleness check (opt-in; requires network access).
    # Audit item 15 — direct attribute access; argparse boolean-flag
    # always defaults to False so a typo would crash here instead of
    # silently disabling the check.
    if args.check_registry:
        registry_findings = _check_module_registry_staleness(all_text)
        print(
            f"# registry check: {len(registry_findings)} stale module(s) found",
            file=sys.stderr,
        )
        findings.extend(registry_findings)

    # Auto-fix application — runs before suppression so the patched file
    # re-scan (if the user re-runs) won't report those findings.
    # Audit item 15 — direct access on argparse-wired flags.
    if args.apply_fixes:
        # Exit after a real apply so the user can re-run to confirm clean state.
        if _cmd_apply_fixes(args, findings, entries):
            return

    # Apply project-wide ignore_rules from .tf-analyze.yaml
    _ignore_rules = project_config.get("ignore_rules") or []
    if _ignore_rules:
        _ignore_set = set(_ignore_rules)
        _before = len(findings)
        findings = [f for f in findings if f["id"] not in _ignore_set]
        _ignored = _before - len(findings)
        if _ignored:
            print(f"# {_ignored} finding(s) suppressed by project ignore_rules", file=sys.stderr)

    # De-duplicate exact-duplicate findings — a whole-file grep rule or
    # overlapping detection passes could emit the same (id, file, line,
    # resource) twice; collapse them so counts/score and every output
    # format see each finding once. Order-preserving.
    _seen_fp: set = set()
    _deduped: list[dict] = []
    for _f in findings:
        _fp = (_f.get("id"), _f.get("file"), _f.get("line"), _f.get("resource"))
        if _fp in _seen_fp:
            continue
        _seen_fp.add(_fp)
        _deduped.append(_f)
    if len(_deduped) != len(findings):
        print(
            f"# {len(findings) - len(_deduped)} duplicate finding(s) collapsed",
            file=sys.stderr,
        )
    findings = _deduped

    # Apply suppressions
    suppressed_findings: list[dict] = []
    if not args.no_suppress and (global_suppressions or file_inline_suppressions):
        findings, suppressed_findings = apply_suppressions(
            findings, file_inline_suppressions, global_suppressions
        )
        if suppressed_findings:
            print(f"# {len(suppressed_findings)} finding(s) suppressed", file=sys.stderr)
    # Tag findings whose suppression just expired so the report can show
    # them in a dedicated section instead of mislabelling them as "new".
    if expired_suppressions:
        for f in findings:
            entry = expired_suppressions.get(f["id"])
            if entry:
                f["was_suppressed_until"] = entry.get("expires")
                f["prior_suppression_reason"] = entry.get("reason", "")

    # Auto-stub generation — scaffold YAML files for either:
    #   (a) IDs explicitly passed via --propose-stub (judgement-pass promotion)
    #   (b) finding IDs that are NOT already in the catalogue (truly novel —
    #       this only happens if findings carry non-catalogue IDs, e.g. from
    #       an external reconciler).
    if args.auto_stub:
        _cmd_auto_stub(args, findings, entries)

    # Build attack graph when requested (consumes all_text + findings)
    attack_graph: dict | None = None
    blast_radius_top: list[dict] = []
    if getattr(args, "attack_graph", False):
        _ri_for_graph = _build_resource_index(all_text)
        attack_graph = build_attack_graph(_ri_for_graph, findings)
        n_nodes = len(attack_graph["nodes"])
        n_path = len(attack_graph["critical_path"])
        print(
            f"# attack graph: {n_nodes} nodes, "
            f"critical path length {n_path}",
            file=sys.stderr,
        )
        _apply_reachability_urgency(findings, attack_graph, {e["id"]: e for e in entries})
        # R30.17 — Blast-radius traversal reuses the attack-graph DAG.
        # Same edge direction works for both attack propagation and
        # destroy propagation: aws_vpc → aws_subnet means VPC compromise
        # spreads to subnet AND VPC destruction breaks subnet. Annotate
        # findings + build a top-N report; JSON always carries it.
        from _blast_radius import (
            compute_blast_radius,
            annotate_findings_with_blast_radius,
            top_blast_radius_resources,
        )
        _blast = compute_blast_radius(attack_graph)
        annotate_findings_with_blast_radius(findings, _blast)
        # Decorate each graph node so the demo UI / VS Code attack-graph
        # panel can scale node radius by downstream impact without a
        # second top-N lookup. Keeps JSON shape backwards-compatible —
        # consumers that ignore the field see no change.
        for _node in attack_graph.get("nodes") or []:
            _node["blast_radius"] = int(_blast.get(_node.get("id", ""), 0))
        blast_radius_top = top_blast_radius_resources(attack_graph, _blast, top_n=10)
        if blast_radius_top:
            print(
                f"# blast radius: top resource '{blast_radius_top[0]['resource']}' "
                f"affects {blast_radius_top[0]['blast_radius']} downstream",
                file=sys.stderr,
            )

    # Fix centrality scoring (requires attack graph)
    centrality_scores: list[dict] | None = None
    if attack_graph and getattr(args, "attack_graph", False):
        centrality_scores = _score_fix_centrality(attack_graph, findings)
        if centrality_scores:
            print(
                f"# fix centrality: top fix is '{centrality_scores[0]['finding_id']}' "
                f"(blocks {centrality_scores[0]['crowns_blocked']} crown jewel(s))",
                file=sys.stderr,
            )

    # Compliance gap report
    compliance_report: dict | None = None
    if getattr(args, "compliance", False) or args.format == "compliance" or getattr(args, "pdf_output", None):
        fw_arg = getattr(args, "compliance_framework", "cis") or "cis"
        compliance_report = _compliance_gap_report(findings, entries, framework=fw_arg)
        if getattr(args, "oscal", None):
            oscal_data = _compliance_to_oscal(
                compliance_report,
                str(args.targets[0]) if args.targets else "",
            )
            oscal_path = Path(args.oscal)
            oscal_path.write_text(json.dumps(oscal_data, indent=2))
            print(f"# OSCAL written to {oscal_path}", file=sys.stderr)
        # R30.13 — Compliance PDF export. Renders the HTML compliance
        # report through weasyprint into a print-shaped PDF the CISO
        # can take to an audit. weasyprint is an optional dep — print
        # an install hint when missing rather than failing silently.
        if getattr(args, "pdf_output", None):
            try:
                from weasyprint import HTML, CSS  # type: ignore
            except ImportError:
                print(
                    "ERROR: --pdf-output requires weasyprint. "
                    "Install with `pip install weasyprint` (depends on "
                    "system libs pango/cairo). Skipping PDF generation.",
                    file=sys.stderr,
                )
                sys.exit(2)
            pdf_path = Path(args.pdf_output)
            # Wrap the compliance HTML fragment in a minimal page so the
            # PDF picks up a title, paper size, and print-friendly styles
            # (page margins, font scaling, anti-orphan headings).
            _comp_html_body = _render_compliance_html(compliance_report)
            page_html = (
                "<!doctype html>\n<html><head><meta charset='utf-8'>"
                "<title>tf-analyze · Compliance Gap Report</title>"
                "<style>"
                "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
                "color:#222;font-size:11pt;line-height:1.4;margin:0;padding:0}"
                "h1,h2,h3{color:#157878;page-break-after:avoid}"
                "h1{font-size:22pt;margin:0 0 6pt 0}"
                "h2{font-size:15pt;border-bottom:2px solid #157878;padding-bottom:3pt}"
                "table{width:100%;border-collapse:collapse;margin:8pt 0;page-break-inside:avoid}"
                "td,th{padding:4pt 6pt;border-bottom:1px solid #ddd;text-align:left}"
                "th{background:#157878;color:#fff;font-weight:600}"
                "code{font-family:'SF Mono',Consolas,monospace;font-size:9pt;background:#f3f4f6;padding:1pt 3pt;border-radius:2pt}"
                "a{color:#157878;text-decoration:none}"
                "</style></head>"
                f"<body><h1>tf-analyze · Compliance Gap Report</h1>"
                f"<p style='color:#666;font-size:9pt'>Framework: <code>{fw_arg}</code>"
                f" · Generated {os.environ.get('TFA_PDF_GEN_TIMESTAMP') or ''}</p>"
                f"{_comp_html_body}"
                f"<hr style='margin-top:18pt;border:none;border-top:1px solid #ccc'/>"
                f"<p style='font-size:8pt;color:#888'>Generated by "
                f"<a href='https://chrisadkin8.github.io/tf-analyze/'>tf-analyze</a> "
                f"— deterministic static analysis with attack-path prioritisation.</p>"
                "</body></html>"
            )
            try:
                HTML(string=page_html).write_pdf(str(pdf_path))
                print(f"# PDF compliance report written to {pdf_path}", file=sys.stderr)
            except Exception as e:
                print(
                    f"ERROR: weasyprint PDF generation failed: {e}",
                    file=sys.stderr,
                )
                sys.exit(2)

    # PR review mode — post inline comments and exit
    if args.mode == "pr-review":
        _pr_review_mode(args, findings, entries)
        if _out_file is not None:
            _out_file.close()
        return

    if getattr(args, "gen_tests", None):
        written = generate_tftest(findings, entries, Path(args.gen_tests))
        print(f"# gen-tests: wrote {len(written)} file(s) to {args.gen_tests}", file=sys.stderr)

    # Enrich findings with catalogue metadata so JSON/SARIF/HTML/LSP
    # consumers (especially the VS Code extension's hover) can render
    # narratives, fix snippets, and MITRE tags without re-loading the
    # catalogue themselves.
    _enrich_findings_for_output(findings, entries)

    # Baseline mode: filter findings against a prior snapshot before
    # everything downstream (output, exit-code, attack-graph). Suppressed
    # findings still appear under suppressed_by_baseline in JSON output.
    suppressed_by_baseline: list[dict] = []
    if getattr(args, "baseline", None):
        retained, suppressed_by_baseline = apply_baseline(
            findings, Path(args.baseline)
        )
        if suppressed_by_baseline:
            print(
                f"# baseline: {len(suppressed_by_baseline)} finding(s) "
                f"matched and suppressed; "
                f"{len(retained)} new",
                file=sys.stderr,
            )
        findings = retained

    # Threat-intel enrichment (R30.2 — KEV + EPSS exploitability ranking).
    # Cross-references each rule's `cwe:` tags with CISA KEV's CWE set
    # so findings touching actively-exploited weakness classes get a 🔥 KEV
    # badge, an optional EPSS score, and (when --rank-by != "urgency") a
    # one-tier urgency promotion. Daily-cached at ~/.cache/tf-analyze/;
    # network failures fall back to cache, missing cache degrades to a
    # no-op (no badges, no promotion).
    rank_by_mode = getattr(args, "rank_by", "urgency")
    allow_network = not getattr(args, "no_threat_intel", False)
    if rank_by_mode != "urgency":
        from _threat_intel import (
            load_kev_cwes, load_epss_scores, enrich_findings,
            rank_findings, warn_on_status,
        )
        kev_cwes, kev_status = load_kev_cwes(allow_network=allow_network)
        warn_on_status("KEV", kev_status)
        # EPSS is optional — without per-rule CVE tags it only kicks in
        # when the catalogue starts shipping `cve:` lists. Load lazily.
        epss_scores: dict[str, float] = {}
        if kev_cwes:
            epss_scores, epss_status = load_epss_scores(allow_network=allow_network)
            warn_on_status("EPSS", epss_status)
        enrich_findings(
            findings, entries,
            rank_by=rank_by_mode,
            kev_cwes=kev_cwes,
            epss_scores=epss_scores,
        )
        findings = rank_findings(findings, rank_by_mode)
        promoted = sum(1 for f in findings if f.get("exploitability_promoted"))
        kev_hits = sum(1 for f in findings if f.get("kev"))
        if kev_hits:
            print(
                f"# exploitability: {kev_hits} finding(s) tagged KEV"
                + (f"; {promoted} promoted urgency tier" if promoted else ""),
                file=sys.stderr,
            )

    # Compute the always-emitted summary block (score, grade, counts).
    # SKILL.md describes the same formula; the constants in detect.py are
    # the single source of truth and the LLM-driven markdown report should
    # cite this same number.
    summary = _compute_summary(findings, suppressed_findings, suppressed_by_baseline)

    # INFO-tier findings (e.g. module-reuse suggestions) are advisory and
    # noisy by default. They stay in `summary["counts"]["INFO"]` for
    # context but only appear in rendered output when --show-info is set.
    # Weight is 0 so the score is unaffected by this filter.
    if not getattr(args, "show_info", False):
        entry_map_for_info = {e["id"]: e for e in entries}
        _info_filtered = [
            f for f in findings
            if _effective_urgency(f, entry_map_for_info.get(f["id"], {})) == "INFO"
        ]
        if _info_filtered:
            findings = [
                f for f in findings
                if _effective_urgency(f, entry_map_for_info.get(f["id"], {})) != "INFO"
            ]
            print(
                f"# {len(_info_filtered)} INFO finding(s) hidden "
                f"(use --show-info to display)",
                file=sys.stderr,
            )

    # Auto-compare: resolve most recent JSON report as the prior when set.
    compare_target = args.compare
    if args.auto_compare and not compare_target:
        prior_json = find_latest_prior(reports_dir, ".json")
        if prior_json:
            compare_target = str(prior_json)
            print(f"# auto-compare against {prior_json}", file=sys.stderr)

    # Report comparison + render — both the --compare delta branch and the
    # normal branch, across every --format. See _render_report.
    _render_report(
        args, findings, entries, emit=_emit, summary=summary,
        suppressed_findings=suppressed_findings,
        suppressed_by_baseline=suppressed_by_baseline,
        attack_graph=attack_graph, centrality_scores=centrality_scores,
        compliance_report=compliance_report,
        blast_radius_top=blast_radius_top, compare_target=compare_target,
    )

    if _out_file is not None:
        _out_file.close()

    # Exit code for CI gating
    if args.fail_on:
        urgency_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        threshold = urgency_rank.get(args.fail_on, 3)
        entry_map = {e["id"]: e for e in entries}
        for f in findings:
            entry = entry_map.get(f["id"])
            if entry:
                finding_rank = urgency_rank.get(_effective_urgency(f, entry), 3)
                if finding_rank <= threshold:
                    sys.exit(1)


# ---- R30.15 topic-module registration -----------------------------------
# Importing each topic module triggers the @_register_infile /
# @_register_corpus decorators inside it, populating _INFILE_HANDLERS
# and _CORPUS_HANDLERS. The imports MUST happen after all module-level
# state in detect.py is defined (regex constants, helper functions,
# the dispatch types) because each topic module imports back from
# `detect` to get those.
#
# When this file is executed as ``python3 scripts/detect.py`` it is
# loaded under the name ``__main__``. A naive ``from detect import …``
# inside a topic module would then re-import detect.py as a *second*
# module called ``detect``, with its own copy of ``_INFILE_HANDLERS``
# — handlers would be registered into the copy and never seen by the
# running ``__main__`` instance. Aliasing ``__main__`` as ``detect``
# in ``sys.modules`` before the topic-module imports ensures the
# back-import resolves to the same module and the handlers land in
# the dict the dispatch loop actually reads.
import sys as _sys
_sys.modules.setdefault("detect", _sys.modules[__name__])
import _handlers_generic  # noqa: E402,F401  (R30.15 — 12 generic primitives)
import _handlers_security  # noqa: E402,F401  (R30.15 — 9 security handlers)
import _handlers_robustness  # noqa: E402,F401  (R30.15 — 14 robustness handlers)
import _handlers_modules  # noqa: E402,F401  (R30.15 — 7 module-lifecycle handlers)
import _handlers_infra  # noqa: E402,F401  (R30.15 — 9 infra/backend/provider handlers)
import _handlers_policy  # noqa: E402,F401  (policy-as-code DSL — kind: policy)


if __name__ == "__main__":
    main()
