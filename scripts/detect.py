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
#
# The skill's default contract is stdlib-only — no pip install required to
# run a scan. python-hcl2 (when installed) provides heredoc-aware
# attribute extraction that the regex path can't match. Off by default,
# enabled per-run via `--use-hcl2` or `TF_ANALYZE_USE_HCL2=1`.
try:
    import hcl2 as _hcl2  # type: ignore
    _HAS_HCL2 = True
except Exception:
    _hcl2 = None  # type: ignore
    _HAS_HCL2 = False

_USE_HCL2 = False  # toggled by main() after argparse


def _enable_hcl2_or_warn() -> None:
    """Flip the fast-path on. Warn and remain in regex mode if hcl2 isn't
    installed — the caller asked for it explicitly and deserves to know
    they're not getting it."""
    global _USE_HCL2
    if not _HAS_HCL2:
        print(
            "WARN: --use-hcl2 requested but python-hcl2 is not installed; "
            "falling back to regex parser. Run `pip install python-hcl2` "
            "to enable the heredoc-aware fast-path.",
            file=sys.stderr,
        )
        return
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

# ---- Minimal YAML loader -------------------------------------------------
# Avoid PyYAML dependency. Catalogue YAML is shallow and well-formed.

def _version_tuple(s: str) -> tuple[int, ...]:
    """Extract the first dotted-numeric sequence from a string."""
    m = re.search(r"(\d+(?:\.\d+)+)", s)
    if not m:
        m = re.search(r"(\d+)", s)
        if not m:
            return ()
    return tuple(int(x) for x in m.group(1).split("."))


def _provider_constraint_allows(constraint: str, min_version: str) -> bool:
    """Does the user's `version =` constraint allow any version
    >= `min_version`? Each comma-separated clause is parsed
    individually (`>=`, `<`, `<=`, `~>`, `=`, `!=`), and the answer is
    "yes" only if no clause excludes versions ≥ `min_version`.

    Behaviour is permissive: an unparseable clause is ignored (rules
    are gated by the readable clauses), and an empty constraint always
    passes.

    Examples:
      ('~> 5.40',          '5.0')  -> True   (5.40 to <6.0 reaches 5.0+)
      ('~> 4.50',          '5.0')  -> False  (4.50 to <5.0 — no 5.x)
      ('>= 4.0',           '5.0')  -> True   (open upper bound)
      ('< 5.0',            '5.0')  -> False  (excludes 5.0+)
      ('>= 1.5.0, < 1.10', '1.10') -> False  (upper bound shuts out 1.10)
      ('>= 1.5.0',         '1.10') -> True   (no upper bound)
      ('',                 '5.0')  -> True   (no constraint = trust user)
    """
    if not constraint:
        return True
    min_v = _version_tuple(min_version)
    if not min_v:
        return True

    def _pad(a: tuple, b: tuple) -> tuple[tuple, tuple]:
        """Right-pad two version tuples with zeros so comparisons treat
        `1.10` and `1.10.0` as equal."""
        n = max(len(a), len(b))
        return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))

    clause_re = re.compile(
        r"^\s*(>=|<=|<|>|~>|!=|=)?\s*(\d+(?:\.\d+)*)\s*$"
    )
    for raw in constraint.split(","):
        m = clause_re.match(raw)
        if not m:
            continue
        op = m.group(1) or "="
        v = tuple(int(x) for x in m.group(2).split("."))
        a, b = _pad(min_v, v)
        if op == "<":
            # Excludes everything >= v. min_v reachable iff min_v < v.
            if a >= b:
                return False
        elif op == "<=":
            if a > b:
                return False
        elif op == "~>":
            if len(v) < 2:
                continue
            upper = list(v)
            upper[-1] = 0
            upper[-2] = upper[-2] + 1
            upper_t = tuple(upper)
            a_lo, b_lo = _pad(min_v, v)
            a_hi, b_hi = _pad(min_v, upper_t)
            if a_lo < b_lo or a_hi >= b_hi:
                return False
        elif op == "=":
            if a != b:
                return False
        elif op == "!=":
            continue
        # `>=` and `>` only set lower bounds — they never exclude
        # min_v from the reachable set.
    return True


def _extract_provider_constraints(all_files_text: dict) -> dict[str, str]:
    """Walk every file's `terraform { required_providers {...} }` block
    and return the per-provider version constraint string. Last-write-
    wins is fine — most repos define `required_providers` in exactly
    one file (versions.tf), and divergent declarations should be flagged
    by ROB-VERSION-002 separately."""
    constraints: dict[str, str] = {}
    tf_block_re = re.compile(r"(?m)^\s*terraform\s*\{")
    rp_block_re = re.compile(r"required_providers\s*\{")
    entry_re = re.compile(
        r'(\w[\w-]*)\s*=\s*\{[^{}]*?version\s*=\s*"([^"]+)"',
        re.DOTALL,
    )
    for text in all_files_text.values():
        for m in tf_block_re.finditer(text):
            depth = 0
            i = m.end() - 1
            end = None
            for j in range(i, len(text)):
                c = text[j]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            if end is None:
                continue
            tf_body = text[m.end():end]
            rp = rp_block_re.search(tf_body)
            if not rp:
                continue
            for em in entry_re.finditer(tf_body[rp.end():]):
                constraints[em.group(1)] = em.group(2)
    return constraints


def _extract_terraform_version(all_files_text: dict) -> str:
    """Pull the user's `terraform { required_version = "..." }` constraint
    string. Last-write-wins across files; ROB-VERSION-002 already flags
    inconsistent declarations separately."""
    rv_re = re.compile(
        r'(?ms)^\s*terraform\s*\{[^}]*?required_version\s*=\s*"([^"]+)"'
    )
    for text in all_files_text.values():
        m = rv_re.search(text)
        if m:
            return m.group(1)
    return ""


def _entry_applies_to_providers(
    entry: dict,
    provider_constraints: dict[str, str],
    terraform_constraint: str = "",
) -> bool:
    """Gate a catalogue entry on its `applies_when:` clause.

    Supported sub-fields:
      * min_provider: { name: version }  — fires only if the user's
        required_providers constraint allows any version >= the listed
        minimum for the named provider.
      * min_terraform: version           — fires only if the target's
        terraform.required_version constraint allows any TF version
        >= the listed minimum.

    No `applies_when` (or unparseable constraint) means the entry runs.
    Behaviour is permissive by design: false positives can be suppressed
    inline; false negatives (skipped rule) are silent.
    """
    aw = entry.get("applies_when") or {}
    mp = aw.get("min_provider") or {}
    for name, min_ver in mp.items():
        user_constraint = provider_constraints.get(name, "")
        if not _provider_constraint_allows(user_constraint, str(min_ver)):
            return False
    min_tf = aw.get("min_terraform")
    if min_tf:
        if not _provider_constraint_allows(
            terraform_constraint, str(min_tf)
        ):
            return False
    return True


def _read_normalized(path: Path) -> str:
    """Read a text file and normalize line endings to LF.

    Without normalization, `text.count('\\n', 0, pos)` undercounts on CRLF
    files: every `\\r\\n` becomes one `\\n` after normalization, and the
    `\\r` carried position offset from the disk byte stream made line
    numbers in findings drift on Windows-edited code. The fix is cheap
    and the substring searches are unaffected.
    """
    return path.read_text().replace("\r\n", "\n").replace("\r", "\n")


def load_yaml(text: str) -> dict:
    """Tiny YAML parser for the catalogue subset we control."""
    root: dict = {}
    stack: list[tuple[int, object]] = [(-1, root)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        # Strip comments outside of strings (catalogue values don't contain `#`)
        line = raw.split("#", 1)[0] if not raw.lstrip().startswith("- ") else raw
        if not line.strip():
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        # Pop stack to current depth.
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        stripped = line.strip()
        # Block scalar (`key: |` followed by indented body)
        if re.match(r"^[A-Za-z_][\w-]*:\s*\|\s*$", stripped):
            key = stripped.split(":", 1)[0]
            i += 1
            body_lines = []
            base_indent = None
            while i < len(lines):
                bl = lines[i]
                if not bl.strip():
                    body_lines.append("")
                    i += 1
                    continue
                bi = len(bl) - len(bl.lstrip())
                if base_indent is None:
                    base_indent = bi
                if bi < base_indent:
                    break
                body_lines.append(bl[base_indent:])
                i += 1
            if isinstance(parent, dict):
                parent[key] = "\n".join(body_lines).rstrip() + "\n"
            continue
        # List item
        if stripped.startswith("- "):
            value = stripped[2:].strip()
            if isinstance(parent, list):
                if ":" in value and not value.startswith("'") and not value.startswith('"'):
                    # Inline mapping start: `- key: val`
                    item: dict = {}
                    k, v = value.split(":", 1)
                    item[k.strip()] = _parse_scalar(v.strip())
                    parent.append(item)
                    stack.append((indent, item))
                else:
                    parent.append(_parse_scalar(value))
            i += 1
            continue
        # `key:` (mapping or container)
        if ":" in stripped:
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                # Container — peek at next non-empty line to decide list vs dict.
                # Skip blank lines AND comment-only lines during peek.
                j = i + 1
                while j < len(lines):
                    peeked = lines[j].strip()
                    if peeked == "" or peeked.startswith("#"):
                        j += 1
                        continue
                    break
                if j < len(lines) and lines[j].lstrip().startswith("- "):
                    container: object = []
                else:
                    container = {}
                if isinstance(parent, dict):
                    parent[key] = container
                stack.append((indent, container))
            else:
                if isinstance(parent, dict):
                    parent[key] = _parse_scalar(rest)
            i += 1
            continue
        i += 1
    return root


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
MODULE_REF_RE = re.compile(r'\bmodule\.([\w-]+)\.([\w-]+)')
INLINE_IGNORE_RE = re.compile(r'#\s*tf-analyze:ignore\s+([\w-]+)')
BOOL_COUNT_RE = re.compile(
    r'^\s*count\s*=\s*.*\?\s*1\s*:\s*0\s*$', re.MULTILINE
)
COUNT_GUARD_RE = re.compile(r'\?|try\s*\(|length\s*\(|one\s*\(')


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


def block_arg_value(body: str, arg: str) -> str | None:
    """Return the literal value of a top-level argument, stripped of quotes/comments.

    Heredoc-bearing values (`arg = <<-EOF\n...\nEOF`) are not handled by the
    regex path — the trailing `<<-EOF` is returned verbatim, which is rarely
    useful. When the optional hcl2 fast-path is enabled
    (`--use-hcl2` or `TF_ANALYZE_USE_HCL2=1`), heredoc bodies are extracted
    structurally so callers see the actual string value.
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


def _resolve_var_ref(val: str, var_defaults: dict) -> str:
    """Resolve plain `var.X` or `local.X` references to their known values.

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
    return val


def _extract_var_defaults_by_dir(all_files_text: dict) -> dict:
    """Return {dir_path: {var_name: default_value}} for all declared variable
    defaults AND locals values.

    Variable scope in Terraform is per-directory.  Locals are stored under
    the key ``__local__<name>`` in the same per-directory dict so that a
    single lookup table can serve both namespaces.
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
                lname, lval = lm.group(1), lm.group(2).strip().strip('"').strip("'")
                result.setdefault(dir_key, {})["__local__" + lname] = lval
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


# ---- Detection ----------------------------------------------------------

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
            if kind == "grep":
                if "regex" not in pat:
                    continue
                regex = re.compile(pat["regex"], re.MULTILINE)
                glob = pat.get("file_glob", "**/*.tf")
                if glob not in ("**/*.tf", "*.tf") and not str(file_path).endswith(
                    glob.lstrip("*/")
                ):
                    continue
                scope = pat.get("scope", "")
                if scope == "resource_body":
                    # Restrict the search to resource block bodies so the pattern
                    # cannot fire on comments, variable descriptions, or output values.
                    rt_filter = pat.get("resource", "")
                    for blk in resources:
                        btype, bname = blk["groups"]
                        if rt_filter and btype != rt_filter:
                            continue
                        if _resource_is_count_zero(blk["body"], _vd):
                            continue
                        if regex.search(blk["body"]):
                            findings.append({
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"{btype}.{bname}",
                            })
                else:
                    search_text = strip_hcl_context(text) if pat.get("hcl_context") else text
                    for m in regex.finditer(search_text):
                        line = search_text.count("\n", 0, m.start()) + 1
                        findings.append({"id": eid, "file": str(file_path), "line": line, "resource": ""})
            elif kind == "resource_arg":
                has_regex = "regex" in pat
                has_not_regex = "not_regex" in pat
                fire_if_absent = pat.get("fire_if_absent", False)
                if "resource" not in pat or "arg" not in pat:
                    continue
                if not has_regex and not has_not_regex:
                    continue
                rt = pat["resource"]
                arg = pat["arg"]
                regex = re.compile(pat["regex"]) if has_regex else None
                not_regex = re.compile(pat["not_regex"]) if has_not_regex else None
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != rt:
                        continue
                    # Skip resources that are definitely not created (count = 0).
                    if _resource_is_count_zero(blk["body"], _vd):
                        continue
                    val = block_arg_value(blk["body"], arg)
                    if val is None:
                        if fire_if_absent:
                            hit = True
                        else:
                            continue
                    else:
                        val = _resolve_var_ref(val, _vd)
                        hit = False
                        if regex and regex.search(val):
                            hit = True
                        if not_regex and not not_regex.search(val):
                            hit = True
                    if hit:
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"{btype}.{bname}",
                            }
                        )
            elif kind == "resource_missing_arg":
                if "resource" not in pat:
                    continue
                rt = pat["resource"]
                arg_path = pat.get("nested_path") or pat.get("arg") or ""
                if not arg_path:
                    continue
                suppress_if = pat.get("suppress_if")
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != rt:
                        continue
                    if _resource_is_count_zero(blk["body"], _vd):
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
                                    actual = _resolve_var_ref(actual, _vd)
                                if actual and str(actual).lower().strip("\"'") == s_val:
                                    continue
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"{btype}.{bname}",
                            }
                        )
            elif kind == "resource_present":
                if "resource" not in pat:
                    continue
                rt = pat["resource"]
                for blk in resources:
                    if blk["groups"][0] == rt:
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
                            }
                        )
            elif kind == "data_source_present":
                if "data_source" not in pat:
                    continue
                dt = pat["data_source"]
                for blk in find_blocks(text, DATA_START):
                    if blk["groups"][0] == dt:
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"data.{blk['groups'][0]}.{blk['groups'][1]}",
                            }
                        )
            elif kind == "firewall_open_port":
                # google_compute_firewall with source_ranges containing
                # 0.0.0.0/0 AND an allow{} block whose `ports` list
                # contains the configured port. Detects the classic
                # "world-open SSH/RDP/SQL" pattern.
                ports = pat.get("ports") or []
                if not ports:
                    continue
                # Accept ints or strings in YAML.
                want_ports = {str(p) for p in ports}
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != "google_compute_firewall":
                        continue
                    body = blk["body"]
                    # Cheap source_ranges check — match either the literal
                    # CIDR or a value that includes it.
                    if "0.0.0.0/0" not in body:
                        continue
                    # Walk every allow{} block; fire if any has a matching port.
                    matched = False
                    for am in re.finditer(r'(?m)^\s*allow\s*\{', body):
                        depth = 0
                        i = am.end() - 1
                        a_end = None
                        while i < len(body):
                            c = body[i]
                            if c == "{":
                                depth += 1
                            elif c == "}":
                                depth -= 1
                                if depth == 0:
                                    a_end = i
                                    break
                            i += 1
                        if a_end is None:
                            continue
                        allow_body = body[am.end():a_end]
                        # Match either `ports = ["22"]` or `ports = ["22","443"]`
                        # or a port range like `"22-22"`.
                        port_match = re.search(
                            r'ports\s*=\s*\[([^\]]+)\]', allow_body
                        )
                        if not port_match:
                            continue
                        listed = re.findall(r'"([^"]+)"', port_match.group(1))
                        for p in listed:
                            if p in want_ports:
                                matched = True
                                break
                            # Range like "20-30" — check if any want_port falls in.
                            if "-" in p:
                                try:
                                    lo, hi = (int(x) for x in p.split("-", 1))
                                except ValueError:
                                    continue
                                for wp in want_ports:
                                    try:
                                        wpi = int(wp)
                                    except ValueError:
                                        continue
                                    if lo <= wpi <= hi:
                                        matched = True
                                        break
                            if matched:
                                break
                        if matched:
                            break
                    if matched:
                        findings.append({
                            "id": eid,
                            "file": str(file_path),
                            "line": blk["start_line"],
                            "resource": f"{btype}.{bname}",
                        })
            elif kind == "resource_body_contains":
                # Fire for every resource of the named type whose body
                # matches the regex. Unlike `grep`, this scopes to a
                # specific resource type and respects block boundaries —
                # the regex doesn't need to limit itself to `[^}]`.
                if "resource" not in pat or "regex" not in pat:
                    continue
                rt = pat["resource"]
                regex = re.compile(pat["regex"], re.MULTILINE | re.DOTALL)
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != rt:
                        continue
                    if regex.search(blk["body"]):
                        findings.append({
                            "id": eid,
                            "file": str(file_path),
                            "line": blk["start_line"],
                            "resource": f"{btype}.{bname}",
                        })
            elif kind == "hcl_attr":
                if "resource" not in pat or "path" not in pat:
                    continue
                rt = pat["resource"]
                path = pat["path"]
                not_equal = pat.get("not_equal")
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != rt:
                        continue
                    parts = path.split(".")
                    parent_body = blk["body"]
                    for p in parts[:-1]:
                        m = re.search(rf'(?m)^\s*{re.escape(p)}\s*\{{', parent_body)
                        if not m:
                            parent_body = None
                            break
                        depth = 0
                        i = m.end() - 1
                        end = None
                        while i < len(parent_body):
                            c = parent_body[i]
                            if c == "{":
                                depth += 1
                            elif c == "}":
                                depth -= 1
                                if depth == 0:
                                    end = i
                                    break
                            i += 1
                        if end is None:
                            parent_body = None
                            break
                        parent_body = parent_body[m.end():end]
                    if parent_body is None:
                        continue
                    val = block_arg_value(parent_body, parts[-1])
                    if val is None:
                        continue
                    if not_equal is not None and str(val).lower() != str(not_equal).lower():
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"{btype}.{bname}",
                            }
                        )
            elif kind == "module_block_missing_arg":
                if "arg" not in pat:
                    continue
                arg = pat["arg"]
                source_re = re.compile(pat.get("source_regex", ".*"))
                for blk in modules:
                    src = block_arg_value(blk["body"], "source") or ""
                    if not source_re.search(src):
                        continue
                    if not block_has_arg(blk["body"], arg):
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"module.{blk['groups'][0]}",
                            }
                        )
            elif kind == "variable_type":
                rgx_str = pat.get("type_regex") or pat.get("regex")
                if not rgx_str:
                    continue
                regex = re.compile(rgx_str)
                for blk in variables:
                    val = block_arg_value(blk["body"], "type")
                    if val is not None and regex.search(val):
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"var.{blk['groups'][0]}",
                            }
                        )
            elif kind == "variable_missing_validation":
                name_re = re.compile(pat.get("name_regex", ".*"))
                for blk in variables:
                    if not name_re.search(blk["groups"][0]):
                        continue
                    if not VALIDATION_BLOCK_RE.search(blk["body"]):
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"var.{blk['groups'][0]}",
                            }
                        )
            elif kind == "moved_block_present":
                moved_blocks = find_simple_blocks(text, MOVED_START)
                for mblk in moved_blocks:
                    findings.append(
                        {
                            "id": eid,
                            "file": str(file_path),
                            "line": mblk["start_line"],
                            "resource": "moved",
                        }
                    )
            elif kind == "removed_block_present":
                removed_blocks = find_simple_blocks(text, REMOVED_START)
                for rblk in removed_blocks:
                    findings.append(
                        {
                            "id": eid,
                            "file": str(file_path),
                            "line": rblk["start_line"],
                            "resource": "removed",
                        }
                    )
            elif kind == "check_block_missing_assert":
                # TF 1.5+ check {} block must contain at least one assert {}.
                # Without one the block is a no-op — usually a half-finished
                # author-time assertion the writer forgot to fill in.
                for cblk in find_blocks(text, CHECK_START):
                    if not re.search(r'(?m)^\s*assert\s*\{', cblk["body"]):
                        findings.append({
                            "id": eid,
                            "file": str(file_path),
                            "line": cblk["start_line"],
                            "resource": f"check.{cblk['groups'][0]}",
                        })
            elif kind == "precondition_missing_error_message":
                # precondition / postcondition blocks should always carry
                # an `error_message`. The TF runtime accepts the block
                # without one, but the failure mode is a generic
                # "condition failed" with no diagnostic — useless on call.
                pre_re = re.compile(
                    r'(?m)^\s*(precondition|postcondition)\s*\{'
                )
                for m in pre_re.finditer(text):
                    # Walk to matching close brace to extract the body.
                    start = m.end() - 1
                    depth = 0
                    end = None
                    for i in range(start, len(text)):
                        c = text[i]
                        if c == "{":
                            depth += 1
                        elif c == "}":
                            depth -= 1
                            if depth == 0:
                                end = i
                                break
                    if end is None:
                        continue
                    body = text[m.end():end]
                    if not re.search(r'(?m)^\s*error_message\s*=', body):
                        line_no = text.count("\n", 0, m.start()) + 1
                        findings.append({
                            "id": eid,
                            "file": str(file_path),
                            "line": line_no,
                            "resource": m.group(1),
                        })
            elif kind == "count_index_ref":
                # Find resources/modules with count, then look for [0]
                # references to them that aren't inside a conditional guard
                counted_names = set()
                for blk in resources:
                    if block_has_arg(blk["body"], "count"):
                        btype, bname = blk["groups"]
                        counted_names.add(f"{btype}.{bname}")
                for blk in modules:
                    if block_has_arg(blk["body"], "count"):
                        counted_names.add(f"module.{blk['groups'][0]}")
                if counted_names:
                    # Search for unguarded [0] references
                    idx_ref_re = re.compile(
                        r'((?:[\w-]+\.[\w-]+(?:\.[\w-]+)?)\[0\]\.[\w-]+)'
                    )
                    for line_no, line_text in enumerate(text.splitlines(), 1):
                        stripped_line = line_text.lstrip()
                        # Skip resource/module declarations, count lines,
                        # comments, and lifecycle blocks
                        if stripped_line.startswith(("#", "//", "resource ", "module ", "count ")):
                            continue
                        for m in idx_ref_re.finditer(line_text):
                            ref = m.group(1)
                            # Extract the base resource name (type.name)
                            ref_parts = ref.split("[")[0]
                            if ref_parts in counted_names:
                                # Check if this line has a conditional guard
                                # (ternary ? or try() or length() > 0)
                                if not COUNT_GUARD_RE.search(line_text):
                                    findings.append(
                                        {
                                            "id": eid,
                                            "file": str(file_path),
                                            "line": line_no,
                                            "resource": ref_parts,
                                        }
                                    )
            elif kind == "count_bool_pattern":
                # Detect count = <expr> ? 1 : 0 on resources and modules
                for blk in resources:
                    if BOOL_COUNT_RE.search(blk["body"]):
                        btype, bname = blk["groups"]
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"{btype}.{bname}",
                            }
                        )
                for blk in modules:
                    if BOOL_COUNT_RE.search(blk["body"]):
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"module.{blk['groups'][0]}",
                            }
                        )
            elif kind == "variable_missing_description":
                for blk in variables:
                    if not DESC_RE.search(blk["body"]):
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"var.{blk['groups'][0]}",
                            }
                        )
            elif kind == "output_missing_description":
                outputs = find_blocks(text, OUTPUT_START)
                for blk in outputs:
                    if not DESC_RE.search(blk["body"]):
                        findings.append(
                            {
                                "id": eid,
                                "file": str(file_path),
                                "line": blk["start_line"],
                                "resource": f"output.{blk['groups'][0]}",
                            }
                        )
            # corpus-level kinds handled in detect_corpus
    return findings


OUTPUT_START = re.compile(r'^\s*output\s+"([\w-]+)"\s*\{', re.MULTILINE)


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

    for entry in entries:
        eid = entry["id"]
        for pat in entry.get("patterns", []) or []:
            kind = pat.get("kind", "")
            if kind == "resource_absent":
                if "resource" not in pat:
                    continue
                rt = pat["resource"]
                # when_present: only fire if a prerequisite resource type exists
                prerequisite = pat.get("when_present")
                if prerequisite:
                    prereq_seen = False
                    for _, text in all_files_text.items():
                        for blk in find_blocks(text, RESOURCE_START):
                            if blk["groups"][0] == prerequisite:
                                prereq_seen = True
                                break
                        if prereq_seen:
                            break
                    if not prereq_seen:
                        continue
                seen = False
                for _, text in all_files_text.items():
                    for blk in find_blocks(text, RESOURCE_START):
                        if blk["groups"][0] == rt:
                            seen = True
                            break
                    if seen:
                        break
                if not seen:
                    findings.append(
                        {
                            "id": eid,
                            "file": str(target),
                            "line": 0,
                            "resource": f"<absent: {rt}>",
                        }
                    )
            elif kind == "output_sensitive_leak":
                for fp, text in all_files_text.items():
                    dirkey = str(Path(fp).parent)
                    for blk in find_blocks(text, OUTPUT_START):
                        if SENSITIVE_TRUE_RE.search(blk["body"]):
                            continue
                        for vm in VAR_REF_RE.finditer(blk["body"]):
                            vname = vm.group(1)
                            if sensitive_vars.get((dirkey, vname)):
                                findings.append(
                                    {
                                        "id": eid,
                                        "file": str(fp),
                                        "line": blk["start_line"],
                                        "resource": f"output.{blk['groups'][0]}",
                                    }
                                )
                                break
            elif kind == "cross_module":
                for fp, text in all_files_text.items():
                    caller_dir = Path(fp).parent
                    for mblk in find_blocks(text, MODULE_START):
                        src = block_arg_value(mblk["body"], "source")
                        if not src or not src.startswith("."):
                            continue
                        child_dir = (caller_dir / src).resolve()
                        arg_re = re.compile(
                            r'(?m)^\s*([\w-]+)\s*=\s*var\.([\w-]+)\s*(?:#.*)?$'
                        )
                        for am in arg_re.finditer(mblk["body"]):
                            child_arg = am.group(1)
                            caller_var = am.group(2)
                            if child_arg == "source":
                                continue
                            if not sensitive_vars.get((str(caller_dir), caller_var)):
                                continue
                            child_marked = False
                            child_found = False
                            for cfp, ctext in all_files_text.items():
                                if Path(cfp).parent.resolve() != child_dir:
                                    continue
                                for cblk in find_blocks(ctext, VARIABLE_START):
                                    if cblk["groups"][0] != child_arg:
                                        continue
                                    child_found = True
                                    if re.search(
                                        r'(?m)^\s*sensitive\s*=\s*true\s*$',
                                        cblk["body"],
                                    ):
                                        child_marked = True
                                    break
                            if child_found and not child_marked:
                                findings.append(
                                    {
                                        "id": eid,
                                        "file": str(fp),
                                        "line": mblk["start_line"],
                                        "resource": f"module.{mblk['groups'][0]}.{child_arg}",
                                    }
                                )
            elif kind == "variable_unused":
                for fp, text in all_files_text.items():
                    dirkey = str(Path(fp).parent)
                    refs = var_refs_by_dir.get(dirkey, set())
                    for blk in find_blocks(text, VARIABLE_START):
                        vname = blk["groups"][0]
                        if vname not in refs:
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"var.{vname}",
                                }
                            )
            elif kind == "output_unused":
                # For each child module directory, check if its outputs are
                # consumed by any caller via module.X.output_name
                for fp, text in all_files_text.items():
                    fp_dir = str(Path(fp).parent)
                    # Find module names whose source resolves to this dir
                    consuming_mod_names = [
                        mn for mn, sd in module_sources.items() if sd == fp_dir
                    ]
                    if not consuming_mod_names:
                        continue  # root module outputs — skip
                    for blk in find_blocks(text, OUTPUT_START):
                        oname = blk["groups"][0]
                        consumed = any(
                            (mn, oname) in output_refs
                            for mn in consuming_mod_names
                        )
                        if not consumed:
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"output.{oname}",
                                }
                            )
            elif kind == "module_missing_tests":
                # Fire once per module directory that has .tf files but no .tftest.hcl
                checked_dirs: set[str] = set()
                for fp in all_files_text:
                    dirkey = str(Path(fp).parent)
                    if dirkey in checked_dirs:
                        continue
                    checked_dirs.add(dirkey)
                    dir_path = Path(dirkey)
                    test_files = list(dir_path.glob("*.tftest.hcl"))
                    # Also check tests/ subdirectory
                    tests_subdir = dir_path / "tests"
                    if tests_subdir.is_dir():
                        test_files.extend(tests_subdir.glob("*.tftest.hcl"))
                    if not test_files:
                        # Pick the first .tf file in this dir for line reference
                        first_tf = None
                        for f in all_files_text:
                            if str(Path(f).parent) == dirkey:
                                first_tf = f
                                break
                        findings.append(
                            {
                                "id": eid,
                                "file": str(first_tf or dirkey),
                                "line": 1,
                                "resource": f"<module:{dir_path.name}>",
                            }
                        )
            elif kind == "backend_inconsistency":
                # Collect all backend blocks across root modules
                backend_re = re.compile(
                    r'^\s*backend\s+"([\w-]+)"\s*\{', re.MULTILINE
                )
                backends: list[tuple[str, str, int]] = []  # (type, file, line)
                for fp, text in all_files_text.items():
                    for m in backend_re.finditer(text):
                        btype = m.group(1)
                        line = text.count("\n", 0, m.start()) + 1
                        backends.append((btype, str(fp), line))
                if len(backends) >= 2:
                    types = set(b[0] for b in backends)
                    if len(types) > 1:
                        # Different backend types — flag all but the first
                        for btype, bfile, bline in backends[1:]:
                            findings.append(
                                {
                                    "id": eid,
                                    "file": bfile,
                                    "line": bline,
                                    "resource": f"backend.{btype}",
                                }
                            )
            elif kind == "backend_missing_arg":
                # Fire when a backend block of the specified type exists but lacks
                # a required argument. Used to catch S3 backends without state locking.
                backend_type = pat.get("backend_type")
                arg = pat.get("arg")
                if not backend_type or not arg:
                    continue
                backend_re = re.compile(
                    r'^\s*backend\s+"' + re.escape(backend_type) + r'"\s*\{',
                    re.MULTILINE,
                )
                arg_re = re.compile(r'\b' + re.escape(arg) + r'\s*=')
                for fp, text in all_files_text.items():
                    for m in backend_re.finditer(text):
                        # Extract block body via brace matching
                        depth, i, end = 0, m.end() - 1, None
                        while i < len(text):
                            c = text[i]
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
                        body = text[m.end():end]
                        if not arg_re.search(body):
                            line = text.count("\n", 0, m.start()) + 1
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": line,
                                    "resource": f"backend.{backend_type}",
                                }
                            )
            elif kind == "templatefile_sensitive_leak":
                # Find templatefile() calls that reference sensitive variables
                tf_call_re = re.compile(
                    r'templatefile\s*\([^,]+,\s*\{([^}]*)\}', re.DOTALL
                )
                var_ref_re = re.compile(r'\bvar\.([\w-]+)')
                for fp, text in all_files_text.items():
                    dirkey = str(Path(fp).parent)
                    for m in tf_call_re.finditer(text):
                        arg_block = m.group(1)
                        for vm in var_ref_re.finditer(arg_block):
                            vname = vm.group(1)
                            if sensitive_vars.get((dirkey, vname)):
                                line = text.count("\n", 0, m.start()) + 1
                                findings.append(
                                    {
                                        "id": eid,
                                        "file": str(fp),
                                        "line": line,
                                        "resource": f"templatefile(var.{vname})",
                                    }
                                )
            elif kind == "remote_state_present":
                for fp, text in all_files_text.items():
                    for blk in find_blocks(text, DATA_START):
                        dtype, dname = blk["groups"]
                        if dtype == "terraform_remote_state":
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"data.terraform_remote_state.{dname}",
                                }
                            )
            elif kind == "provider_alias_unused":
                # Collect (alias_name, file, line) from provider blocks with alias
                alias_decls: list[tuple[str, str, str, int]] = []
                for fp, text in all_files_text.items():
                    for blk in find_blocks(text, PROVIDER_START):
                        pname = blk["groups"][0]
                        alias = block_arg_value(blk["body"], "alias")
                        if alias:
                            alias_decls.append((pname, alias, str(fp), blk["start_line"]))
                # Scan all files for `provider = pname.alias` or
                # `providers = { ... = pname.alias }` references.
                ref_re = re.compile(r'\b([\w-]+)\.([\w-]+)\b')
                refs: set[tuple[str, str]] = set()
                for text in all_files_text.values():
                    # Strip comments so a reference mentioned in a fixture
                    # header like `# google.eu declared but never used` is
                    # not counted as a real HCL reference.
                    stripped = strip_hcl_context(text)
                    for m in ref_re.finditer(stripped):
                        refs.add((m.group(1), m.group(2)))
                for pname, alias, fp, line in alias_decls:
                    if (pname, alias) not in refs:
                        findings.append(
                            {
                                "id": eid,
                                "file": fp,
                                "line": line,
                                "resource": f"provider.{pname}.{alias}",
                            }
                        )
            elif kind == "provider_alias_module_mismatch":
                # Collect declared aliases per file-scope, then check module
                # `providers = { … = pname.alias }` references resolve.
                declared: set[tuple[str, str]] = set()
                for text in all_files_text.values():
                    for blk in find_blocks(text, PROVIDER_START):
                        pname = blk["groups"][0]
                        alias = block_arg_value(blk["body"], "alias")
                        if alias:
                            declared.add((pname, alias))
                providers_block_re = re.compile(
                    r'(?m)^\s*providers\s*=\s*\{([^}]*)\}', re.DOTALL
                )
                entry_re = re.compile(r'=\s*([\w-]+)\.([\w-]+)')
                for fp, text in all_files_text.items():
                    for mblk in find_blocks(text, MODULE_START):
                        pm = providers_block_re.search(mblk["body"])
                        if not pm:
                            continue
                        for em in entry_re.finditer(pm.group(1)):
                            pname, alias = em.group(1), em.group(2)
                            if (pname, alias) not in declared:
                                findings.append(
                                    {
                                        "id": eid,
                                        "file": str(fp),
                                        "line": mblk["start_line"],
                                        "resource": f"module.{mblk['groups'][0]}:{pname}.{alias}",
                                    }
                                )
            elif kind == "foreach_over_list":
                list_rhs_re = re.compile(
                    r'(?m)^\s*for_each\s*=\s*(\[|tolist\(|toset\s*\(\s*\[)'
                )
                for fp, text in all_files_text.items():
                    for blk in find_blocks(text, RESOURCE_START):
                        m = list_rhs_re.search(blk["body"])
                        # toset([...]) is the idiomatic fix; flag only raw
                        # list literal or tolist(...) calls
                        if m and m.group(1) != "toset ([":
                            if m.group(1).startswith("toset"):
                                continue
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"{blk['groups'][0]}.{blk['groups'][1]}",
                                }
                            )
            elif kind == "count_length_unguarded":
                # Resources with count = length(X); flag any [N]/[count.index]
                # reference that isn't guarded by length()/try()/ternary.
                counted: dict[str, int] = {}  # "type.name" -> declaration line
                for fp, text in all_files_text.items():
                    length_count_re = re.compile(
                        r'(?m)^\s*count\s*=\s*length\s*\('
                    )
                    for blk in find_blocks(text, RESOURCE_START):
                        if length_count_re.search(blk["body"]):
                            key = f"{blk['groups'][0]}.{blk['groups'][1]}"
                            counted[key] = blk["start_line"]
                if counted:
                    idx_re = re.compile(
                        r'([\w-]+\.[\w-]+)\[(\d+|count\.index)\]'
                    )
                    for fp, text in all_files_text.items():
                        for i, line_text in enumerate(text.splitlines(), 1):
                            if "length(" in line_text or "try(" in line_text:
                                continue
                            if re.search(r'\?\s*', line_text):
                                continue
                            for m in idx_re.finditer(line_text):
                                if m.group(1) in counted:
                                    findings.append(
                                        {
                                            "id": eid,
                                            "file": str(fp),
                                            "line": i,
                                            "resource": m.group(1),
                                        }
                                    )
            elif kind == "count_foreach_mix":
                # Per-directory: does any file use count AND for_each on
                # different resources? This is an anti-pattern that makes
                # module consumers deal with both splat and dynamic refs.
                per_dir: dict[str, dict[str, list[dict]]] = {}
                for fp, text in all_files_text.items():
                    dirkey = str(Path(fp).parent)
                    per_dir.setdefault(dirkey, {"count": [], "foreach": []})
                    for blk in find_blocks(text, RESOURCE_START):
                        if COUNT_ATTR_RE.search(blk["body"]):
                            per_dir[dirkey]["count"].append(
                                {"file": str(fp), "line": blk["start_line"],
                                 "resource": f"{blk['groups'][0]}.{blk['groups'][1]}"}
                            )
                        if FOREACH_ATTR_RE.search(blk["body"]):
                            per_dir[dirkey]["foreach"].append(
                                {"file": str(fp), "line": blk["start_line"],
                                 "resource": f"{blk['groups'][0]}.{blk['groups'][1]}"}
                            )
                for dirkey, buckets in per_dir.items():
                    if buckets["count"] and buckets["foreach"]:
                        # Flag the `count` users (for_each is the idiomatic form).
                        for f in buckets["count"]:
                            findings.append({"id": eid, **f})
            elif kind == "data_external_injection":
                for fp, text in all_files_text.items():
                    for blk in find_blocks(text, DATA_START):
                        if blk["groups"][0] != "external":
                            continue
                        # Look for `program = [ ... var.X ... ]`
                        prog_re = re.compile(
                            r'(?m)^\s*program\s*=\s*\[(.*?)\]', re.DOTALL
                        )
                        pm = prog_re.search(blk["body"])
                        if pm and re.search(r'var\.[\w-]+', pm.group(1)):
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"data.external.{blk['groups'][1]}",
                                }
                            )
            elif kind == "tfstate_in_repo":
                # Directory walk once per target
                seen_dirs: set[str] = set()
                for fp in all_files_text:
                    d = Path(fp).parent
                    if str(d) in seen_dirs:
                        continue
                    seen_dirs.add(str(d))
                    for p in d.rglob("*.tfstate*"):
                        if ".terraform" in p.parts:
                            continue
                        findings.append(
                            {
                                "id": eid,
                                "file": str(p),
                                "line": 1,
                                "resource": p.name,
                            }
                        )
                    break  # walk from the outermost target once
            elif kind == "submodule_version_missing":
                # A directory containing .tf but lacking required_version
                # anywhere — common in submodules that inherit the root's
                # constraint only implicitly.
                dirs_with_tf: dict[str, list[str]] = {}
                for fp, text in all_files_text.items():
                    dirs_with_tf.setdefault(str(Path(fp).parent), []).append(fp)
                for d, files in dirs_with_tf.items():
                    has_req = any(
                        re.search(r'required_version\s*=', all_files_text[f])
                        for f in files
                    )
                    if not has_req:
                        findings.append(
                            {
                                "id": eid,
                                "file": str(files[0]),
                                "line": 1,
                                "resource": f"<module:{Path(d).name}>",
                            }
                        )
            elif kind == "providers_version_missing":
                # Find terraform { required_providers { ... } } blocks and
                # flag any provider entry that lacks a version constraint.
                tf_block_re = re.compile(r"(?m)^\s*terraform\s*\{")
                rp_block_re = re.compile(r"required_providers\s*\{")
                # Matches a provider entry: name = { ... }
                entry_re = re.compile(
                    r"(\w[\w-]*)\s*=\s*\{([^{}]+)\}", re.DOTALL
                )
                for fp, text in all_files_text.items():
                    for tf_m in tf_block_re.finditer(text):
                        depth = 0
                        i = tf_m.end() - 1
                        tf_end = None
                        while i < len(text):
                            if text[i] == "{":
                                depth += 1
                            elif text[i] == "}":
                                depth -= 1
                                if depth == 0:
                                    tf_end = i
                                    break
                            i += 1
                        if tf_end is None:
                            continue
                        tf_body = text[tf_m.end():tf_end]
                        rp = rp_block_re.search(tf_body)
                        if not rp:
                            continue
                        # Extract only the required_providers inner block
                        rp_start = tf_m.end() + rp.end()
                        depth = 1
                        j = rp_start
                        rp_end = None
                        while j < len(text):
                            if text[j] == "{":
                                depth += 1
                            elif text[j] == "}":
                                depth -= 1
                                if depth == 0:
                                    rp_end = j
                                    break
                            j += 1
                        if rp_end is None:
                            continue
                        rp_body = text[rp_start:rp_end]
                        for em in entry_re.finditer(rp_body):
                            provider_name = em.group(1)
                            entry_body = em.group(2)
                            if not re.search(r"\bversion\s*=", entry_body):
                                # Find the line number
                                entry_pos = rp_start + em.start()
                                line_no = text.count("\n", 0, entry_pos) + 1
                                findings.append({
                                    "id": eid,
                                    "file": str(fp),
                                    "line": line_no,
                                    "resource": f"<provider:{provider_name}>",
                                })
            elif kind == "prod_no_deletion_protection":
                # Heuristic: resources in a file path containing 'prod' or
                # labels mentioning prod, with deletion_protection=false or
                # absent on supported resources.
                protected_types = {
                    "google_sql_database_instance",
                    "google_compute_instance",
                    "google_bigquery_dataset",
                    "google_container_cluster",
                    "google_storage_bucket",
                }
                for fp, text in all_files_text.items():
                    path_is_prod = "prod" in str(fp).lower()
                    for blk in find_blocks(text, RESOURCE_START):
                        btype, bname = blk["groups"]
                        if btype not in protected_types:
                            continue
                        body = blk["body"]
                        label_prod = bool(re.search(
                            r'environment\s*=\s*"prod', body
                        ))
                        if not (path_is_prod or label_prod):
                            continue
                        dp = block_arg_value(body, "deletion_protection")
                        # Catalogue accepts `lifecycle.prevent_destroy = true`
                        # as equivalent — required for buckets/datasets which
                        # don't expose `deletion_protection` at the top level.
                        prevent_destroy = block_has_nested_path(
                            body, "lifecycle.prevent_destroy"
                        )
                        if (dp is None or str(dp).lower() == "false") and not prevent_destroy:
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"{btype}.{bname}",
                                }
                            )
            elif kind == "deprecated_datasource":
                deprecated_types = set(
                    (pat.get("types") or "").split(",")
                ) or {"template_file"}
                for fp, text in all_files_text.items():
                    for blk in find_blocks(text, DATA_START):
                        if blk["groups"][0] in deprecated_types:
                            findings.append(
                                {
                                    "id": eid,
                                    "file": str(fp),
                                    "line": blk["start_line"],
                                    "resource": f"data.{blk['groups'][0]}.{blk['groups'][1]}",
                                }
                            )
            elif kind == "intent_gap":
                subkind = pat.get("subkind", "")
                if subkind == "var_name_false_default":
                    for fp, ftext in all_files_text.items():
                        for blk in find_blocks(ftext, VARIABLE_START):
                            name = blk["groups"][0]
                            desc = block_arg_value(blk["body"], "description") or ""
                            if _INTENT_SECURITY_NAME_RE.search(name) or _INTENT_SECURITY_NAME_RE.search(desc):
                                if _INTENT_FALSE_DEFAULT_RE.search(blk["body"]):
                                    findings.append({
                                        "id": eid,
                                        "file": str(fp),
                                        "line": blk["start_line"],
                                        "resource": f"variable.{name}",
                                    })
                elif subkind == "var_desc_must_no_validation":
                    for fp, ftext in all_files_text.items():
                        for blk in find_blocks(ftext, VARIABLE_START):
                            name = blk["groups"][0]
                            desc = block_arg_value(blk["body"], "description") or ""
                            if _INTENT_MUST_TRUE_RE.search(desc):
                                if not _INTENT_VALIDATION_RE.search(blk["body"]):
                                    findings.append({
                                        "id": eid,
                                        "file": str(fp),
                                        "line": blk["start_line"],
                                        "resource": f"variable.{name}",
                                    })
                elif subkind == "prod_tag_no_deletion_protection":
                    for fp, ftext in all_files_text.items():
                        for blk in find_blocks(ftext, RESOURCE_START):
                            btype, bname = blk["groups"]
                            if _INTENT_PROD_TAG_RE.search(blk["body"]):
                                if _INTENT_DEL_PROT_FALSE_RE.search(blk["body"]):
                                    addr = f"{btype}.{bname}"
                                    findings.append({
                                        "id": eid,
                                        "file": str(fp),
                                        "line": blk["start_line"],
                                        "resource": addr,
                                    })
                elif subkind == "prod_tag_force_destroy":
                    for fp, ftext in all_files_text.items():
                        for blk in find_blocks(ftext, RESOURCE_START):
                            btype, bname = blk["groups"]
                            if _INTENT_PROD_TAG_RE.search(blk["body"]):
                                if _INTENT_FORCE_DESTROY_TRUE_RE.search(blk["body"]):
                                    addr = f"{btype}.{bname}"
                                    findings.append({
                                        "id": eid,
                                        "file": str(fp),
                                        "line": blk["start_line"],
                                        "resource": addr,
                                    })
            elif kind == "graph_check":
                # Cross-resource detector. The pattern names a registered
                # graph function; we dispatch to it with a uniform index of
                # all resources keyed by `<type>.<name>` → block dict.
                fn_name = pat.get("function")
                fn = _GRAPH_CHECKS.get(fn_name)
                if not fn:
                    continue
                if "_resource_index_cache" not in locals():
                    _resource_index_cache = _build_resource_index(all_files_text)
                for finding in fn(_resource_index_cache, all_files_text):
                    finding["id"] = eid
                    findings.append(finding)
    return findings


# ---- Graph-based checks ---------------------------------------------------
#
# A graph check is a function that takes a resource index plus the raw file
# map and yields zero or more partial findings (id is filled in by the
# caller). Graph checks are how we express conditions that span multiple
# resources, e.g. "logging target bucket is itself private".
#
# To add a new graph check:
#   1. Write the function below (signature: index, files -> list[finding]).
#   2. Register it in _GRAPH_CHECKS.
#   3. Reference it from a catalogue YAML via `kind: graph_check, function: <name>`.

def _build_resource_index(all_files_text: dict) -> dict:
    """Index every resource block by `<type>.<name>` → {file, line, body}."""
    idx: dict[str, dict] = {}
    for fp, text in all_files_text.items():
        for blk in find_blocks(text, RESOURCE_START):
            btype, bname = blk["groups"]
            idx[f"{btype}.{bname}"] = {
                "file": str(fp),
                "line": blk["start_line"],
                "body": blk["body"],
                "type": btype,
                "name": bname,
            }
    return idx


_LOG_BUCKET_REF = re.compile(
    r'log_bucket\s*=\s*google_storage_bucket\.([\w-]+)\.name',
)


def _graph_logging_target_public(index: dict, all_files_text: dict) -> list[dict]:
    """A bucket's logging.log_bucket references a bucket lacking
    public_access_prevention = "enforced". The target accumulates audit logs
    for the source — leaking it via public access is a high-blast-radius bug.
    """
    out: list[dict] = []
    for addr, src in index.items():
        if src["type"] != "google_storage_bucket":
            continue
        m = _LOG_BUCKET_REF.search(src["body"])
        if not m:
            continue
        target_addr = f"google_storage_bucket.{m.group(1)}"
        target = index.get(target_addr)
        if not target:
            continue
        pap = block_arg_value(target["body"], "public_access_prevention")
        if pap != "enforced":
            out.append({
                "file": target["file"],
                "line": target["line"],
                "resource": target_addr,
                "context": (
                    f"logging target of {addr} (in {src['file']}:{src['line']}) "
                    f"is missing public_access_prevention=enforced"
                ),
            })
    return out


_NODEPOOL_CLUSTER_REF = re.compile(
    r'cluster\s*=\s*google_container_cluster\.([\w-]+)(?:\.\w+)?',
)
_SECURE_BOOT_RE = re.compile(r'enable_secure_boot\s*=\s*true')
_INTEGRITY_MON_RE = re.compile(r'enable_integrity_monitoring\s*=\s*true')


def _graph_gke_nodepool_secure_boot(index: dict, all_files_text: dict) -> list[dict]:
    """Every google_container_node_pool attached to a cluster must set
    `node_config.shielded_instance_config.enable_secure_boot = true` AND
    `enable_integrity_monitoring = true`. CIS GKE 6.5.5 requires both on
    every pool — leaving any pool unhardened nullifies the cluster-wide
    posture, since pods schedule across pools.
    """
    out: list[dict] = []
    for addr, np in index.items():
        if np["type"] != "google_container_node_pool":
            continue
        m = _NODEPOOL_CLUSTER_REF.search(np["body"])
        if not m:
            continue  # ambient/data-source cluster reference — out of scope
        body = np["body"]
        missing = []
        if not _SECURE_BOOT_RE.search(body):
            missing.append("enable_secure_boot")
        if not _INTEGRITY_MON_RE.search(body):
            missing.append("enable_integrity_monitoring")
        if missing:
            out.append({
                "file": np["file"],
                "line": np["line"],
                "resource": addr,
                "context": (
                    f"node pool attached to google_container_cluster.{m.group(1)} "
                    f"is missing: {', '.join(missing)}"
                ),
            })
    return out


_KEY_RING_REF = re.compile(
    r'key_ring\s*=\s*google_kms_key_ring\.([\w-]+)(?:\.\w+)?',
)
_KMS_KEY_REF = re.compile(
    r'kms_key_name\s*=\s*google_kms_crypto_key\.([\w-]+)(?:\.\w+)?',
)


def _graph_kms_location_parity(index: dict, all_files_text: dict) -> list[dict]:
    """A KMS-encrypted resource's location must match the key ring's
    location. KMS keys inherit `location` from the key ring; if the
    consuming resource (bucket, SQL instance, etc.) lives in a different
    region, the encrypt/decrypt path crosses regions, breaks regional
    durability guarantees, and quietly degrades to multi-region pricing.
    """
    out: list[dict] = []
    # First pass: for each crypto key, find the location of its key ring.
    key_ring_loc: dict[str, str | None] = {}
    for addr, blk in index.items():
        if blk["type"] != "google_kms_crypto_key":
            continue
        m = _KEY_RING_REF.search(blk["body"])
        if not m:
            continue
        ring_addr = f"google_kms_key_ring.{m.group(1)}"
        ring = index.get(ring_addr)
        if not ring:
            continue
        key_ring_loc[addr] = block_arg_value(ring["body"], "location")
    # Second pass: any resource referencing a crypto key must match.
    for addr, consumer in index.items():
        if consumer["type"] in {"google_kms_crypto_key", "google_kms_key_ring"}:
            continue
        m = _KMS_KEY_REF.search(consumer["body"])
        if not m:
            continue
        key_addr = f"google_kms_crypto_key.{m.group(1)}"
        ring_loc = key_ring_loc.get(key_addr)
        if not ring_loc:
            continue
        consumer_loc = (
            block_arg_value(consumer["body"], "location")
            or block_arg_value(consumer["body"], "region")
        )
        if not consumer_loc:
            continue
        if consumer_loc.lower() != ring_loc.lower():
            out.append({
                "file": consumer["file"],
                "line": consumer["line"],
                "resource": addr,
                "context": (
                    f"location {consumer_loc!r} does not match KMS key ring "
                    f"location {ring_loc!r} (via {key_addr})"
                ),
            })
    return out


_PROJECT_IAM_TYPES = {
    "google_project_iam_member",
    "google_project_iam_binding",
}
_RESOURCE_LEVEL_TYPES = {
    "google_storage_bucket_iam_member",
    "google_storage_bucket_iam_binding",
    "google_pubsub_topic_iam_member",
    "google_pubsub_subscription_iam_member",
    "google_secret_manager_secret_iam_member",
    "google_kms_crypto_key_iam_member",
    "google_bigquery_dataset_iam_member",
}


def _graph_iam_member_breadth(index: dict, all_files_text: dict) -> list[dict]:
    """A service account that already has resource-level IAM (e.g. on a
    specific bucket / topic) and ALSO has a project-level IAM binding is
    almost certainly over-privileged: the project-level grant supersedes
    the resource-level scoping, making the latter pointless. Either
    remove the project grant or remove the resource-level one.
    """
    out: list[dict] = []
    member_re = re.compile(r'member\s*=\s*"([^"]+)"')
    members_re = re.compile(r'members\s*=\s*\[([^\]]+)\]')
    project_grants: dict[str, list[dict]] = {}
    resource_grants: dict[str, list[dict]] = {}
    for addr, blk in index.items():
        members: set[str] = set()
        m = member_re.search(blk["body"])
        if m:
            members.add(m.group(1))
        m = members_re.search(blk["body"])
        if m:
            for tok in m.group(1).split(","):
                tok = tok.strip().strip('"')
                if tok:
                    members.add(tok)
        if blk["type"] in _PROJECT_IAM_TYPES:
            for mem in members:
                project_grants.setdefault(mem, []).append({"addr": addr, "blk": blk})
        elif blk["type"] in _RESOURCE_LEVEL_TYPES:
            for mem in members:
                resource_grants.setdefault(mem, []).append({"addr": addr, "blk": blk})
    for mem, project_list in project_grants.items():
        resource_list = resource_grants.get(mem)
        if not resource_list:
            continue
        for pg in project_list:
            out.append({
                "file": pg["blk"]["file"],
                "line": pg["blk"]["line"],
                "resource": pg["addr"],
                "context": (
                    f"member {mem} also has resource-level IAM at "
                    f"{', '.join(g['addr'] for g in resource_list)} — "
                    f"the project-level grant makes those redundant"
                ),
            })
    return out


_UAMI_PRINCIPAL_REF = re.compile(
    r'azurerm_user_assigned_identity\.([\w-]+)\.principal_id'
)


def _graph_azure_uami_orphan(index: dict, all_files_text: dict) -> list[dict]:
    """Detect azurerm_user_assigned_identity resources with no
    azurerm_role_assignment referencing their principal_id — an orphan
    identity that grants no permissions yet still widens the blast radius
    of a tenant compromise (an attacker who can assign roles can weaponise it).
    """
    out: list[dict] = []
    uamis = {k: v for k, v in index.items()
             if v["type"] == "azurerm_user_assigned_identity"}
    if not uamis:
        return out
    referenced: set[str] = set()
    for addr, res in index.items():
        if res["type"] != "azurerm_role_assignment":
            continue
        for m in _UAMI_PRINCIPAL_REF.finditer(res["body"]):
            referenced.add(m.group(1))
    for addr, res in uamis.items():
        if res["name"] not in referenced:
            out.append(
                {
                    "file": res["file"],
                    "line": res["line"],
                    "resource": addr,
                    "context": (
                        "UAMI has no azurerm_role_assignment binding — "
                        "orphan identity widens blast radius without granting intent"
                    ),
                }
            )
    return out


def _graph_dynamodb_pitr(index: dict, all_files_text: dict) -> list[dict]:
    """aws_dynamodb_table without point_in_time_recovery { enabled = true }.

    DynamoDB's PITR default is disabled. A table with no
    point_in_time_recovery block (or enabled = false) cannot be restored
    to an arbitrary second within the last 35 days, leaving accidental
    writes or deletes unrecoverable.
    """
    out: list[dict] = []
    for addr, res in index.items():
        if res["type"] != "aws_dynamodb_table":
            continue
        body = res["body"]
        pitr_m = re.search(r'(?m)^\s*point_in_time_recovery\s*\{', body)
        if not pitr_m:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        depth, k, end = 0, pitr_m.end() - 1, None
        while k < len(body):
            c = body[k]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = k
                    break
            k += 1
        if end is None:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        pitr_body = body[pitr_m.end():end]
        enabled = block_arg_value(pitr_body, "enabled")
        if not enabled or enabled.lower() != "true":
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
    return out


def _graph_dynamodb_sse(index: dict, all_files_text: dict) -> list[dict]:
    """aws_dynamodb_table without a customer-managed KMS key for SSE.

    DynamoDB encrypts at rest by default using Amazon-owned keys, which
    cannot be audited, rotated, or revoked. Tables that lack a
    server_side_encryption block with kms_key_arn rely on these default
    keys instead of a customer-managed key (CMK).
    """
    out: list[dict] = []
    for addr, res in index.items():
        if res["type"] != "aws_dynamodb_table":
            continue
        body = res["body"]
        sse_m = re.search(r'(?m)^\s*server_side_encryption\s*\{', body)
        if not sse_m:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        depth, k, end = 0, sse_m.end() - 1, None
        while k < len(body):
            c = body[k]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = k
                    break
            k += 1
        if end is None:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        sse_body = body[sse_m.end():end]
        if not block_has_arg(sse_body, "kms_key_arn"):
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
    return out


_GRAPH_CHECKS = {
    "logging_target_public": _graph_logging_target_public,
    "gke_nodepool_secure_boot": _graph_gke_nodepool_secure_boot,
    "kms_location_parity": _graph_kms_location_parity,
    "iam_member_breadth": _graph_iam_member_breadth,
    "azure_uami_orphan": _graph_azure_uami_orphan,
    "dynamodb_pitr": _graph_dynamodb_pitr,
    "dynamodb_sse": _graph_dynamodb_sse,
}


# ---- attack graph --------------------------------------------------------

_CROWN_JEWEL_TYPES: set[str] = {
    "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance",
    "aws_secretsmanager_secret", "aws_kms_key", "aws_s3_bucket",
    "google_sql_database_instance", "google_secret_manager_secret",
    "google_kms_crypto_key", "google_storage_bucket",
    "azurerm_mssql_server", "azurerm_sql_server",
    "azurerm_key_vault", "azurerm_key_vault_secret", "azurerm_storage_account",
    # Azure — expanded crown jewels
    "azurerm_postgresql_server", "azurerm_postgresql_flexible_server",
    "azurerm_cosmosdb_account", "azurerm_service_bus_namespace",
    "azurerm_mysql_server", "azurerm_mysql_flexible_server",
}

_NODE_TYPE_MAP: dict[str, str] = {
    "aws_instance": "compute", "aws_lambda_function": "compute",
    "aws_ecs_task_definition": "compute", "aws_ecs_service": "compute",
    "google_compute_instance": "compute", "google_cloud_run_v2_service": "compute",
    "google_cloud_run_service": "compute", "google_container_cluster": "compute",
    "google_cloudfunctions_function": "compute", "google_cloudfunctions2_function": "compute",
    "azurerm_linux_virtual_machine": "compute",
    "azurerm_windows_virtual_machine": "compute", "azurerm_virtual_machine": "compute",
    "azurerm_app_service": "compute", "azurerm_linux_web_app": "compute",
    "azurerm_windows_web_app": "compute", "azurerm_kubernetes_cluster": "compute",
    "azurerm_function_app": "compute", "azurerm_linux_function_app": "compute",
    "aws_iam_role": "iam", "aws_iam_instance_profile": "iam", "aws_iam_policy": "iam",
    "google_service_account": "iam",
    "azurerm_user_assigned_identity": "iam", "azurerm_role_assignment": "iam",
    "aws_s3_bucket": "storage", "google_storage_bucket": "storage",
    "azurerm_storage_account": "storage",
    "aws_db_instance": "storage", "aws_rds_cluster": "storage",
    "google_sql_database_instance": "storage", "azurerm_mssql_server": "storage",
    "azurerm_postgresql_server": "storage", "azurerm_postgresql_flexible_server": "storage",
    "azurerm_mysql_server": "storage", "azurerm_cosmosdb_account": "storage",
    "aws_secretsmanager_secret": "secret",
    "google_secret_manager_secret": "secret",
    "azurerm_key_vault_secret": "secret",
    "aws_kms_key": "key", "google_kms_crypto_key": "key",
    "azurerm_key_vault_key": "key", "azurerm_key_vault": "key",
    "aws_security_group": "network", "aws_lb": "network", "aws_alb": "network",
    "google_compute_firewall": "network", "azurerm_network_security_group": "network",
    "azurerm_public_ip": "network",
}

# Internet-reachability detection regexes
_INET_EC2_PUBLIC_IP_RE  = re.compile(r'associate_public_ip_address\s*=\s*true')
_INET_RDS_PUBLIC_RE     = re.compile(r'publicly_accessible\s*=\s*true')
_INET_SQL_PUBLIC_IP_RE  = re.compile(r'ipv4_enabled\s*=\s*true')
_INET_SG_CIDR_RE        = re.compile(r'cidr_blocks\s*=\s*\[.*?"0\.0\.0\.0/0"', re.DOTALL)
_INET_SG_IPV6_RE        = re.compile(r'ipv6_cidr_blocks\s*=\s*\[.*?"::/0"', re.DOTALL)
_INET_CLOUDRUN_ALL_RE   = re.compile(r'ingress\s*=\s*"?INGRESS_TRAFFIC_ALL"?')
_INET_ALB_FACING_RE     = re.compile(r'(?:scheme|load_balancer_type)\s*=\s*"?internet-facing"?')
_INET_GCE_ACCESS_CFG_RE = re.compile(r'access_config\s*\{')
_INET_GKE_PRIVATE_RE    = re.compile(r'private_cluster_config\s*\{')
# Azure reachability
_INET_AZ_IP_RESTRICTION_RE = re.compile(r'ip_restriction\s*\{')

# Edge-inference regexes (HCL reference patterns between resources)
_EDGE_IAM_PROFILE_RE  = re.compile(
    r'iam_instance_profile\s*=\s*aws_iam_instance_profile\.([\w-]+)')
_EDGE_PROFILE_ROLE_RE = re.compile(
    r'\brole\s*=\s*aws_iam_role\.([\w-]+)(?:\.\w+)?')
_EDGE_KMS_KEY_ID_RE   = re.compile(
    r'kms_key_id\s*=\s*aws_kms_key\.([\w-]+)(?:\.\w+)?')
_EDGE_KMS_KEY_NAME_RE = re.compile(
    r'kms_key_name\s*=\s*google_kms_crypto_key\.([\w-]+)(?:\.\w+)?')
_EDGE_KMS_MASTER_RE   = re.compile(
    r'kms_master_key_id\s*=\s*(?:aws_kms_key|google_kms_crypto_key)\.([\w-]+)(?:\.\w+)?')
_EDGE_SECRET_ARN_RE   = re.compile(
    r'secrets_manager_secret_arn\s*=\s*aws_secretsmanager_secret\.([\w-]+)(?:\.\w+)?')
_EDGE_SG_REF_RE       = re.compile(
    r'(?:vpc_security_group_ids|security_groups)\s*=\s*\[[^\]]*aws_security_group\.([\w-]+)')
_EDGE_GCP_SA_RE       = re.compile(
    r'email\s*=\s*google_service_account\.([\w-]+)(?:\.\w+)?')
_EDGE_GCS_BUCKET_RE   = re.compile(
    r'\bbucket\s*=\s*google_storage_bucket\.([\w-]+)(?:\.\w+)?')
# Azure edge-inference (managed identity, Key Vault, storage, SQL)
_EDGE_AZ_MI_RE        = re.compile(
    r'identity_ids\s*=\s*\[[^\]]*azurerm_user_assigned_identity\.([\w-]+)')
_EDGE_AZ_KV_RE        = re.compile(
    r'key_vault_id\s*=\s*azurerm_key_vault\.([\w-]+)(?:\.\w+)?')
_EDGE_AZ_STORAGE_RE   = re.compile(
    r'storage_account_name\s*=\s*azurerm_storage_account\.([\w-]+)(?:\.\w+)?')
_EDGE_AZ_SQL_RE       = re.compile(
    r'server_name\s*=\s*azurerm_mssql_server\.([\w-]+)(?:\.\w+)?')
# GCP additional service-account references (Cloud Run, GKE, Cloud Functions)
_EDGE_GCP_SA_EMAIL_RE = re.compile(
    r'service_account_email\s*=\s*google_service_account\.([\w-]+)(?:\.\w+)?')
_EDGE_GCP_SA_NAME_RE  = re.compile(
    r'(?<!\w)service_account\s*=\s*google_service_account\.([\w-]+)(?:\.\w+)?')


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


def _is_internet_reachable(rtype: str, body: str) -> bool:
    """Return True if the resource type + body suggests it is directly internet-reachable."""
    if rtype == "aws_instance":
        return bool(_INET_EC2_PUBLIC_IP_RE.search(body))
    if rtype in {"aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance"}:
        return bool(_INET_RDS_PUBLIC_RE.search(body))
    if rtype == "google_sql_database_instance":
        return bool(_INET_SQL_PUBLIC_IP_RE.search(body))
    if rtype == "aws_security_group":
        return bool(_INET_SG_CIDR_RE.search(body) or _INET_SG_IPV6_RE.search(body))
    if rtype in {"google_cloud_run_v2_service", "google_cloud_run_service"}:
        return bool(_INET_CLOUDRUN_ALL_RE.search(body) or "ingress" not in body)
    if rtype in {"aws_lb", "aws_alb"}:
        return bool(_INET_ALB_FACING_RE.search(body))
    if rtype == "google_compute_instance":
        return bool(_INET_GCE_ACCESS_CFG_RE.search(body))
    if rtype == "google_container_cluster":
        return not bool(_INET_GKE_PRIVATE_RE.search(body))
    # Azure — public_ip resource is always internet-facing by definition
    if rtype == "azurerm_public_ip":
        return True
    # Azure web/function apps are public unless ip_restriction blocks are present
    if rtype in {
        "azurerm_app_service", "azurerm_linux_web_app",
        "azurerm_windows_web_app", "azurerm_function_app",
        "azurerm_linux_function_app",
    }:
        return not bool(_INET_AZ_IP_RESTRICTION_RE.search(body))
    return False


def build_attack_graph(resource_index: dict, findings: list[dict]) -> dict:
    """Build a directed attack-path graph from internet-reachable nodes to crown jewels.

    Returns a dict with keys: nodes, edges, critical_path, internet_node_id.
    Nodes carry: id, type, label, file, line, findings, internet_reachable,
    is_crown_jewel, on_critical_path.
    Edges carry: from, to, label.
    """
    # Index findings by resource address
    finding_by_resource: dict[str, list[str]] = {}
    for f in findings:
        res = f.get("resource", "")
        if res:
            finding_by_resource.setdefault(res, []).append(f["id"])

    # Build nodes for every resource
    nodes: dict[str, dict] = {}
    for addr, res in resource_index.items():
        rtype = res["type"]
        reachable = _is_internet_reachable(rtype, res["body"])
        nodes[addr] = {
            "id": addr,
            "type": _NODE_TYPE_MAP.get(rtype, "compute"),
            "label": addr,
            "file": res["file"],
            "line": res["line"],
            "findings": finding_by_resource.get(addr, []),
            "internet_reachable": reachable,
            "is_crown_jewel": rtype in _CROWN_JEWEL_TYPES,
            "on_critical_path": False,
        }

    # Synthetic internet entry node
    nodes["INTERNET"] = {
        "id": "INTERNET",
        "type": "internet",
        "label": "Internet",
        "file": "",
        "line": 0,
        "findings": [],
        "internet_reachable": True,
        "is_crown_jewel": False,
        "on_critical_path": False,
    }

    # Infer edges from HCL reference patterns
    edges: list[dict] = []

    def _add_edge(src: str, dst: str, label: str) -> None:
        if src in nodes and dst in nodes and src != dst:
            edges.append({"from": src, "to": dst, "label": label})

    for addr, res in resource_index.items():
        body = res["body"]
        rtype = res["type"]

        for m in _EDGE_IAM_PROFILE_RE.finditer(body):
            _add_edge(addr, f"aws_iam_instance_profile.{m.group(1)}", "iam_profile")
        if rtype == "aws_iam_instance_profile":
            for m in _EDGE_PROFILE_ROLE_RE.finditer(body):
                _add_edge(addr, f"aws_iam_role.{m.group(1)}", "role")
        elif rtype not in {"aws_iam_instance_profile"}:
            for m in _EDGE_PROFILE_ROLE_RE.finditer(body):
                _add_edge(addr, f"aws_iam_role.{m.group(1)}", "role")
        for m in _EDGE_KMS_KEY_ID_RE.finditer(body):
            _add_edge(addr, f"aws_kms_key.{m.group(1)}", "kms_key")
        for m in _EDGE_KMS_KEY_NAME_RE.finditer(body):
            _add_edge(addr, f"google_kms_crypto_key.{m.group(1)}", "kms_key")
        for m in _EDGE_KMS_MASTER_RE.finditer(body):
            if "aws_kms_key" in m.group(0):
                _add_edge(addr, f"aws_kms_key.{m.group(1)}", "kms_master_key")
            else:
                _add_edge(addr, f"google_kms_crypto_key.{m.group(1)}", "kms_master_key")
        for m in _EDGE_SECRET_ARN_RE.finditer(body):
            _add_edge(addr, f"aws_secretsmanager_secret.{m.group(1)}", "secret_ref")
        for m in _EDGE_SG_REF_RE.finditer(body):
            _add_edge(addr, f"aws_security_group.{m.group(1)}", "security_group")
        for m in _EDGE_GCP_SA_RE.finditer(body):
            _add_edge(addr, f"google_service_account.{m.group(1)}", "service_account")
        for m in _EDGE_GCS_BUCKET_RE.finditer(body):
            _add_edge(addr, f"google_storage_bucket.{m.group(1)}", "bucket_ref")
        # Azure edges
        for m in _EDGE_AZ_MI_RE.finditer(body):
            _add_edge(addr, f"azurerm_user_assigned_identity.{m.group(1)}", "managed_identity")
        for m in _EDGE_AZ_KV_RE.finditer(body):
            _add_edge(addr, f"azurerm_key_vault.{m.group(1)}", "key_vault_ref")
        for m in _EDGE_AZ_STORAGE_RE.finditer(body):
            _add_edge(addr, f"azurerm_storage_account.{m.group(1)}", "storage_ref")
        for m in _EDGE_AZ_SQL_RE.finditer(body):
            _add_edge(addr, f"azurerm_mssql_server.{m.group(1)}", "sql_server_ref")
        # GCP additional service account reference patterns
        for m in _EDGE_GCP_SA_EMAIL_RE.finditer(body):
            _add_edge(addr, f"google_service_account.{m.group(1)}", "service_account")
        for m in _EDGE_GCP_SA_NAME_RE.finditer(body):
            _add_edge(addr, f"google_service_account.{m.group(1)}", "service_account")

    # Connect internet-reachable nodes to INTERNET
    for addr, node in list(nodes.items()):
        if addr != "INTERNET" and node["internet_reachable"]:
            edges.append({"from": "INTERNET", "to": addr, "label": "internet"})

    # Propagate reachability: compute → SG (internet-reachable) → mark compute reachable
    sg_reachable = {
        e["to"] for e in edges
        if e["from"] == "INTERNET" and nodes.get(e["to"], {}).get("type") == "network"
    }
    for e in edges:
        if e["label"] == "security_group" and e["to"] in sg_reachable:
            src = e["from"]
            if src in nodes and not nodes[src]["internet_reachable"]:
                nodes[src]["internet_reachable"] = True
                edges.append({"from": "INTERNET", "to": src, "label": "internet (via sg)"})

    # BFS: shortest path from INTERNET to each crown jewel
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])

    from collections import deque

    def _bfs(start: str, goal: str) -> list[str]:
        queue: deque[list[str]] = deque([[start]])
        visited: set[str] = {start}
        while queue:
            path = queue.popleft()
            if path[-1] == goal:
                return path
            for nbr in adj.get(path[-1], []):
                if nbr not in visited:
                    visited.add(nbr)
                    queue.append(path + [nbr])
        return []

    crown_jewels = [addr for addr, n in nodes.items() if n["is_crown_jewel"]]
    critical_path: list[str] = []
    for cj in crown_jewels:
        path = _bfs("INTERNET", cj)
        if path and (not critical_path or len(path) < len(critical_path)):
            critical_path = path

    for nid in critical_path:
        if nid in nodes:
            nodes[nid]["on_critical_path"] = True

    # Prune to a manageable size for large repos (keep relevant nodes + neighbors)
    node_list = list(nodes.values())
    if len(node_list) > 60:
        keep = set(critical_path)
        keep.update(addr for addr, n in nodes.items() if n["internet_reachable"])
        keep.update(addr for addr, n in nodes.items() if n["is_crown_jewel"])
        keep.add("INTERNET")
        # add immediate neighbors of keep set
        for e in edges:
            if e["from"] in keep:
                keep.add(e["to"])
            if e["to"] in keep:
                keep.add(e["from"])
        node_list = [n for n in node_list if n["id"] in keep]
        edges = [e for e in edges if e["from"] in keep and e["to"] in keep]

    return {
        "nodes": node_list,
        "edges": edges,
        "critical_path": critical_path,
        "internet_node_id": "INTERNET",
    }


def _score_fix_centrality(graph: dict, findings: list[dict]) -> list[dict]:
    """Rank findings by how many crown-jewel attack paths they block when fixed.

    For each finding's resource, remove that node from the graph and re-run BFS
    from INTERNET to each crown jewel.  The drop in reachable crown jewels is the
    primary 'crowns_blocked' score; secondary signals reward critical-path and
    internet-reachable nodes.  Returns a list sorted by impact (descending).
    """
    if not graph or not graph.get("nodes"):
        return []

    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])

    crown_jewels: frozenset[str] = frozenset(
        n["id"] for n in graph["nodes"] if n.get("is_crown_jewel")
    )

    def _reachable_crowns(exclude: str) -> int:
        visited: set[str] = set()
        queue = ["INTERNET"]
        count = 0
        while queue:
            cur = queue.pop(0)
            if cur in visited or cur == exclude:
                continue
            visited.add(cur)
            if cur in crown_jewels:
                count += 1
            for nxt in adj.get(cur, []):
                if nxt not in visited and nxt != exclude:
                    queue.append(nxt)
        return count

    baseline = _reachable_crowns("")
    if baseline == 0:
        return []

    results: list[dict] = []
    seen: set[str] = set()
    for f in findings:
        res = f.get("resource", "")
        if not res or res in seen or res not in nodes_by_id:
            continue
        seen.add(res)
        after = _reachable_crowns(res)
        blocked = baseline - after
        node = nodes_by_id[res]
        score = blocked * 10
        if node.get("on_critical_path"):
            score += 5
        if node.get("internet_reachable"):
            score += 3
        results.append({
            "finding_id": f["id"],
            "resource": res,
            "impact": score,
            "crowns_blocked": blocked,
            "on_critical_path": node.get("on_critical_path", False),
            "internet_reachable": node.get("internet_reachable", False),
        })

    return sorted(results, key=lambda x: (-x["impact"], x["finding_id"]))


def _apply_reachability_urgency(
    findings: list[dict],
    graph: dict,
    entry_map: dict[str, dict],
) -> None:
    """Promote findings on critical-path resources by one urgency tier;
    demote findings on resources unreachable from INTERNET by one tier."""
    critical_path_set = set(graph.get("critical_path", []))
    internet_reachable_set = {
        n["id"] for n in graph.get("nodes", []) if n.get("internet_reachable")
    }
    for f in findings:
        resource = f.get("resource", "")
        entry = entry_map.get(f["id"], {})
        base = entry.get("default_urgency", "MEDIUM")
        idx = _URGENCY_TIERS.index(base) if base in _URGENCY_TIERS else 1
        if resource and resource in critical_path_set:
            f["urgency"] = _URGENCY_TIERS[min(idx + 1, len(_URGENCY_TIERS) - 1)]
            f["on_critical_path"] = True
        elif resource and resource not in internet_reachable_set:
            f["urgency"] = _URGENCY_TIERS[max(idx - 1, 0)]
        else:
            f["urgency"] = base


def _mermaid_id(addr: str) -> str:
    """Sanitize a resource address for use as a Mermaid node ID."""
    return addr.replace(".", "_").replace("-", "_")


def graph_to_mermaid(graph: dict) -> str:
    """Convert an attack graph to a Mermaid flowchart string."""
    crit_set = set(graph.get("critical_path", []))
    lines = ["```mermaid", "flowchart LR"]
    lines += [
        "    classDef internet fill:#1a1a2e,color:#fff,stroke:#fff",
        "    classDef critical fill:#c0392b,color:#fff,stroke:#ff4444,stroke-width:3px",
        "    classDef crown fill:#6b0000,color:#ffd700,stroke:#ffd700",
        "    classDef reachable fill:#d35400,color:#fff",
        "    classDef iam fill:#6c5ce7,color:#fff",
        "    classDef storage fill:#27ae60,color:#fff",
        "    classDef secret fill:#e74c3c,color:#fff",
        "    classDef key fill:#e67e22,color:#fff",
        "    classDef network fill:#7f8c8d,color:#fff",
        "    classDef compute fill:#2980b9,color:#fff",
    ]

    for node in graph["nodes"]:
        nid = _mermaid_id(node["id"])
        lbl = node["label"].replace('"', "'")
        if node["is_crown_jewel"]:
            lbl = f"👑 {lbl}"
        if node["type"] == "internet":
            shape = f'((("{lbl}")))'
        elif node["type"] in {"secret", "key"}:
            shape = f'{{"{lbl}"}}'
        elif node["type"] == "storage":
            shape = f'[("{lbl}")]'
        else:
            shape = f'["{lbl}"]'
        lines.append(f"    {nid}{shape}")
        if node["id"] in crit_set:
            lines.append(f"    class {nid} critical")
        elif node["is_crown_jewel"]:
            lines.append(f"    class {nid} crown")
        elif node["internet_reachable"] and node["id"] != "INTERNET":
            lines.append(f"    class {nid} reachable")
        else:
            lines.append(f"    class {nid} {node['type']}")

    for edge in graph["edges"]:
        fid = _mermaid_id(edge["from"])
        tid = _mermaid_id(edge["to"])
        lbl = edge.get("label", "")
        f_crit = edge["from"] in crit_set
        t_crit = edge["to"] in crit_set
        arrow = "==>" if (f_crit and t_crit) else "-->"
        if lbl:
            lines.append(f'    {fid} {arrow}|"{lbl}"| {tid}')
        else:
            lines.append(f"    {fid} {arrow} {tid}")

    lines.append("```")
    return "\n".join(lines)


def _render_graph_html(graph: dict) -> str:
    """Return self-contained HTML+JS for an interactive force-directed attack graph."""
    import json as _json
    graph_json = _json.dumps(graph)

    return f"""<div style="margin-bottom:.5em">
  <span style="font-size:12px;color:#666">
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#1a1a2e;vertical-align:middle"></span> Internet &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#2980b9;vertical-align:middle"></span> Compute &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#6c5ce7;vertical-align:middle"></span> IAM &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#27ae60;vertical-align:middle"></span> Storage &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#e74c3c;vertical-align:middle"></span> Secret &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#e67e22;vertical-align:middle"></span> Key &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#7f8c8d;vertical-align:middle"></span> Network &nbsp;
    <span style="border:2px solid #ff4444;display:inline-block;width:12px;height:12px;border-radius:50%;vertical-align:middle;background:#c0392b"></span> Critical path &nbsp;
    <span style="border:2px solid #ffd700;display:inline-block;width:12px;height:12px;border-radius:50%;vertical-align:middle;background:#6b0000"></span> Crown jewel
  </span>
</div>
<div id="ag-wrap" style="position:relative;width:100%;height:580px;background:#f8f9fa;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden">
  <svg id="ag-svg" width="100%" height="100%" style="display:block;cursor:grab">
    <defs>
      <marker id="ag-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#aaa"/>
      </marker>
      <marker id="ag-arr-red" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#c0392b"/>
      </marker>
    </defs>
    <g id="ag-edges-g"></g>
    <g id="ag-nodes-g"></g>
  </svg>
  <div id="ag-sb" style="position:absolute;right:0;top:0;width:270px;height:100%;background:rgba(255,255,255,.97);border-left:1px solid #ddd;padding:14px;box-sizing:border-box;overflow-y:auto;display:none;font-size:13px">
    <button onclick="document.getElementById('ag-sb').style.display='none'"
      style="float:right;border:none;background:none;font-size:16px;cursor:pointer;color:#666">✕</button>
    <h4 id="ag-sb-title" style="margin:0 0 .6em;font-size:14px;word-break:break-all"></h4>
    <div id="ag-sb-body"></div>
  </div>
</div>
<script>
(function(){{
  var G={graph_json};
  var CRIT=new Set(G.critical_path);
  var svgEl=document.getElementById('ag-svg');
  var W=svgEl.parentElement.clientWidth||900, H=580;
  var NS='http://www.w3.org/2000/svg';
  var COLORS={{internet:'#1a1a2e',compute:'#2980b9',iam:'#6c5ce7',storage:'#27ae60',
               secret:'#e74c3c',key:'#e67e22',network:'#7f8c8d'}};
  // Compute pill dimensions for a node (resource name + type prefix, two lines)
  function pillDims(n){{
    var parts=n.label.split('.');
    var name=parts.length>1?parts[parts.length-1]:n.label;
    var typeStr=parts.length>1?parts.slice(0,-1).join('.'):'';
    var dispName=name.length>18?name.slice(0,16)+'…':name;
    var dispType=typeStr.length>24?typeStr.slice(0,22)+'…':typeStr;
    var twoLine=typeStr.length>0;
    // approximate char widths: name at 10px bold ~6.2px, type at 7.5px ~4.6px
    var pw=Math.max(dispName.length*6.2+24,twoLine?dispType.length*4.6+24:0,62);
    var ph=twoLine?36:26;
    return {{hw:pw/2,hh:ph/2,pw:pw,ph:ph,dispName:dispName,dispType:dispType,twoLine:twoLine}};
  }}
  // Clip line endpoint to the rectangular pill boundary of a node
  function clipPt(sx,sy,tx,ty,hw,hh){{
    var dx=sx-tx,dy=sy-ty,dist=Math.sqrt(dx*dx+dy*dy)||1;
    var nx=dx/dist,ny=dy/dist;
    var tc=Math.abs(nx)>1e-9?hw/Math.abs(nx):1e9;
    var tcc=Math.abs(ny)>1e-9?hh/Math.abs(ny):1e9;
    var t=Math.min(tc,tcc);
    return [tx+nx*t,ty+ny*t];
  }}
  // initialise node positions
  var TYPE_ORDER={{internet:0,compute:1,network:2,iam:3,storage:4,secret:5,key:6}};
  var nodes=G.nodes.map(function(n){{
    return Object.assign({{}},n,{{x:W/2,y:H/2,vx:0,vy:0}});
  }});
  var byId={{}};
  nodes.forEach(function(n){{byId[n.id]=n;}});
  var edges=G.edges.map(function(e){{
    return Object.assign({{}},e,{{s:byId[e.from],t:byId[e.to]}});
  }}).filter(function(e){{return e.s&&e.t;}});

  // Pill dims must be ready before tick() so collision resolution can use them
  nodes.forEach(function(n){{var d=pillDims(n);n._hw=d.hw;n._hh=d.hh;}});

  // Structured initial placement: one column per resource type, rows within each group.
  // This gives the physics a much better starting configuration than a random blob.
  (function(){{
    var groups={{}};
    nodes.forEach(function(n){{(groups[n.type]=groups[n.type]||[]).push(n);}});
    var types=Object.keys(groups).sort(function(a,b){{
      return (TYPE_ORDER[a]!==undefined?TYPE_ORDER[a]:5)-(TYPE_ORDER[b]!==undefined?TYPE_ORDER[b]:5);
    }});
    var nc=types.length||1;
    types.forEach(function(t,ti){{
      var g=groups[t];
      g.forEach(function(n,i){{
        n.x=W*(ti+0.5)/nc+(Math.random()-.5)*18;
        n.y=H*(i+0.5)/g.length+(Math.random()-.5)*10;
      }});
    }});
  }})();

  // force tick: Coulomb repulsion + Hooke spring + pill collision resolution + gravity
  var REP=4000,SL=140,SK=0.04,GV=0.008,DMP=0.82,CPAD=14;
  function tick(){{
    var i,j,a,b,dx,dy,d,f,fx,fy,nx2,ny2,hwS,hhS,sep,push;
    for(i=0;i<nodes.length;i++){{
      for(j=i+1;j<nodes.length;j++){{
        a=nodes[i];b=nodes[j];
        dx=a.x-b.x;dy=a.y-b.y;d=Math.sqrt(dx*dx+dy*dy)||1;
        f=REP/(d*d);fx=f*dx/d;fy=f*dy/d;
        a.vx+=fx;a.vy+=fy;b.vx-=fx;b.vy-=fy;
      }}
    }}
    edges.forEach(function(e){{
      dx=e.t.x-e.s.x;dy=e.t.y-e.s.y;d=Math.sqrt(dx*dx+dy*dy)||1;
      f=SK*(d-SL);fx=f*dx/d;fy=f*dy/d;
      e.s.vx+=fx;e.s.vy+=fy;e.t.vx-=fx;e.t.vy-=fy;
    }});
    // Pill collision: if two nodes are closer than their combined pill extents (+padding),
    // push them apart with a force proportional to the overlap. The minimum separation
    // in direction (nx2,ny2) is derived from the ellipse-approximated Minkowski sum of
    // the two pill bounding boxes.
    for(i=0;i<nodes.length;i++){{
      for(j=i+1;j<nodes.length;j++){{
        a=nodes[i];b=nodes[j];
        dx=a.x-b.x;dy=a.y-b.y;d=Math.sqrt(dx*dx+dy*dy)||1;
        nx2=dx/d;ny2=dy/d;
        hwS=a._hw+b._hw+CPAD;
        hhS=a._hh+b._hh+CPAD;
        sep=hwS*hhS/Math.sqrt(hhS*hhS*nx2*nx2+hwS*hwS*ny2*ny2);
        if(d<sep){{
          push=(sep-d)*0.55;
          a.vx+=push*nx2;a.vy+=push*ny2;
          b.vx-=push*nx2;b.vy-=push*ny2;
        }}
      }}
    }}
    nodes.forEach(function(n){{
      n.vx+=GV*(W/2-n.x);n.vy+=GV*(H/2-n.y);
      n.vx*=DMP;n.vy*=DMP;n.x+=n.vx;n.y+=n.vy;
      n.x=Math.max(n._hw+8,Math.min(W-n._hw-8,n.x));
      n.y=Math.max(n._hh+8,Math.min(H-n._hh-8,n.y));
    }});
  }}
  for(var _i=0;_i<400;_i++)tick();

  // SVG helpers
  function svgEl2(tag,attrs,parent){{
    var e=document.createElementNS(NS,tag);
    Object.keys(attrs).forEach(function(k){{e.setAttribute(k,attrs[k]);}});
    if(parent)parent.appendChild(e);
    return e;
  }}

  var egG=document.getElementById('ag-edges-g');
  var ndG=document.getElementById('ag-nodes-g');

  // draw edges clipped to pill boundaries so arrowheads land at the node border
  var lineEls=edges.map(function(e){{
    var isCrit=CRIT.has(e.from)&&CRIT.has(e.to);
    var p1=clipPt(e.t.x,e.t.y,e.s.x,e.s.y,e.s._hw,e.s._hh);
    var p2=clipPt(e.s.x,e.s.y,e.t.x,e.t.y,e.t._hw,e.t._hh);
    var line=svgEl2('line',{{
      x1:p1[0],y1:p1[1],x2:p2[0],y2:p2[1],
      stroke:isCrit?'#c0392b':'#bbb',
      'stroke-width':isCrit?'2.5':'1.2',
      'marker-end':isCrit?'url(#ag-arr-red)':'url(#ag-arr)'
    }},egG);
    var lbl=null;
    if(e.label){{
      lbl=svgEl2('text',{{
        x:(e.s.x+e.t.x)/2,y:(e.s.y+e.t.y)/2,
        'font-size':'8.5','fill':'#aaa','text-anchor':'middle','pointer-events':'none'
      }},egG);
      lbl.textContent=e.label;
    }}
    return {{line:line,lbl:lbl,e:e}};
  }});

  // draw nodes as pill-shaped rectangles with two-line labels
  var nodeEls=nodes.map(function(n){{
    var d=pillDims(n);
    var g=svgEl2('g',{{'transform':'translate('+n.x+','+n.y+')','style':'cursor:pointer'}},ndG);
    var fill=n.on_critical_path?'#c0392b':n.is_crown_jewel?'#6b0000':
             n.internet_reachable&&n.id!=='INTERNET'?'#d35400':
             (COLORS[n.type]||'#2980b9');
    var stroke=n.is_crown_jewel?'#ffd700':'rgba(0,0,0,.18)';
    var sw=n.is_crown_jewel?'2.5':'1';
    svgEl2('rect',{{x:-d.hw,y:-d.hh,width:d.pw,height:d.ph,rx:d.hh,
      fill:fill,stroke:stroke,'stroke-width':sw}},g);
    // primary label: resource name, bold
    var nameEl=svgEl2('text',{{'text-anchor':'middle','fill':'#fff','pointer-events':'none'}},g);
    var ns1=document.createElementNS(NS,'tspan');
    ns1.setAttribute('x','0');
    ns1.setAttribute('dy',d.twoLine?'-3':'4');
    ns1.setAttribute('font-size','10');
    ns1.setAttribute('font-weight','600');
    ns1.textContent=d.dispName;
    nameEl.appendChild(ns1);
    if(d.twoLine){{
      var ns2=document.createElementNS(NS,'tspan');
      ns2.setAttribute('x','0');
      ns2.setAttribute('dy','13');
      ns2.setAttribute('font-size','7.5');
      ns2.setAttribute('fill','rgba(255,255,255,0.62)');
      ns2.textContent=d.dispType;
      nameEl.appendChild(ns2);
    }}
    g.addEventListener('click',function(){{showSb(n);}});
    return {{g:g,n:n}};
  }});

  function redraw(){{
    lineEls.forEach(function(el){{
      var p1=clipPt(el.e.t.x,el.e.t.y,el.e.s.x,el.e.s.y,el.e.s._hw,el.e.s._hh);
      var p2=clipPt(el.e.s.x,el.e.s.y,el.e.t.x,el.e.t.y,el.e.t._hw,el.e.t._hh);
      el.line.setAttribute('x1',p1[0]);el.line.setAttribute('y1',p1[1]);
      el.line.setAttribute('x2',p2[0]);el.line.setAttribute('y2',p2[1]);
      if(el.lbl){{
        el.lbl.setAttribute('x',(el.e.s.x+el.e.t.x)/2);
        el.lbl.setAttribute('y',(el.e.s.y+el.e.t.y)/2);
      }}
    }});
    nodeEls.forEach(function(el){{
      el.g.setAttribute('transform','translate('+el.n.x+','+el.n.y+')');
    }});
  }}

  // animation cool-down
  var alpha=1;
  function animate(){{
    if(alpha>0.005){{
      tick();tick();tick();redraw();
      alpha*=0.96;
      requestAnimationFrame(animate);
    }}
  }}
  animate();

  // drag
  var dragging=null,dragOX=0,dragOY=0;
  svgEl.addEventListener('mousedown',function(ev){{
    var rect=svgEl.getBoundingClientRect();
    var mx=ev.clientX-rect.left,my=ev.clientY-rect.top;
    nodes.forEach(function(n){{
      if(Math.abs(n.x-mx)<n._hw+4&&Math.abs(n.y-my)<n._hh+4){{
        dragging=n;dragOX=mx-n.x;dragOY=my-n.y;
      }}
    }});
    if(dragging)ev.preventDefault();
  }});
  svgEl.addEventListener('mousemove',function(ev){{
    if(!dragging)return;
    var rect=svgEl.getBoundingClientRect();
    dragging.x=ev.clientX-rect.left-dragOX;
    dragging.y=ev.clientY-rect.top-dragOY;
    dragging.vx=0;dragging.vy=0;
    redraw();
  }});
  svgEl.addEventListener('mouseup',function(){{dragging=null;}});
  svgEl.addEventListener('mouseleave',function(){{dragging=null;}});

  // sidebar
  function showSb(n){{
    document.getElementById('ag-sb-title').textContent=n.label;
    var html='<b>Type:</b> '+n.type+'<br>';
    if(n.file)html+='<b>File:</b> <code style="font-size:11px">'+n.file+'</code>:'+n.line+'<br>';
    if(n.is_crown_jewel)html+='<span style="color:#8b0000;font-weight:600">&#128081; Crown Jewel</span><br>';
    if(n.on_critical_path)html+='<span style="color:#c0392b;font-weight:600">&#9888; On Critical Attack Path</span><br>';
    if(n.internet_reachable&&n.id!=='INTERNET')html+='<span style="color:#d35400">&#127760; Internet-reachable</span><br>';
    if(n.findings&&n.findings.length){{
      html+='<br><b>Findings:</b><ul style="margin:.3em 0;padding-left:1.2em">';
      n.findings.forEach(function(f){{html+='<li><code>'+f+'</code></li>';}});
      html+='</ul>';
    }}else{{html+='<br><i style="color:#999">No findings on this resource</i>';}}
    document.getElementById('ag-sb-body').innerHTML=html;
    document.getElementById('ag-sb').style.display='block';
  }}
}})();
</script>"""


# ---- SARIF output --------------------------------------------------------

SARIF_HELP_URI_BASE = (
    "https://github.com/ChrisAdkin8/tf-analyze/blob/main/"
    "catalog/{id}.yaml"
)


def _sarif_fingerprint(finding: dict) -> dict:
    """Return partial fingerprints for SARIF.

    Two complementary keys:
    - tfAnalyze/v1: id|file|resource — changes when file is renamed (new/resolved pair)
    - tfAnalyze/v1-resource: id|resource — stable across file renames; GitHub Code
      Scanning uses the highest-specificity key that matches, so renaming a file
      no longer floods the "fixed" view with false positives when the resource
      name is preserved.
    """
    import hashlib
    full_key = f"{finding['id']}|{finding.get('file','')}|{finding.get('resource','')}"
    resource_key = f"{finding['id']}|{finding.get('resource','')}"
    return {
        "tfAnalyze/v1": hashlib.sha256(full_key.encode()).hexdigest()[:16],
        "tfAnalyze/v1-resource": hashlib.sha256(resource_key.encode()).hexdigest()[:16],
    }


def _effective_urgency(finding: dict, entry: dict) -> str:
    """Return the urgency for a finding: reachability-adjusted if present, else catalogue default."""
    return finding.get("urgency") or entry.get("default_urgency", "MEDIUM")


def to_sarif(findings: list[dict], entries: list[dict]) -> dict:
    """Convert findings to SARIF v2.1.0 format."""
    rules = []
    rule_index = {}
    level_map = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    severity_map = {
        "CRITICAL": "9.5",
        "HIGH": "7.5",
        "MEDIUM": "5.0",
        "LOW": "3.0",
        "INFO": "1.0",
    }
    for entry in entries:
        eid = entry["id"]
        if eid in rule_index:
            continue
        rule_index[eid] = len(rules)
        urgency = entry.get("default_urgency", "MEDIUM")
        recommendation = entry.get("recommendation") or entry.get("title", eid)
        rules.append({
            "id": eid,
            "name": eid,
            "shortDescription": {"text": entry.get("title", eid)},
            "fullDescription": {"text": entry.get("title", eid)},
            "help": {
                "text": recommendation.strip() if isinstance(recommendation, str) else str(recommendation),
                "markdown": recommendation if isinstance(recommendation, str) else str(recommendation),
            },
            "helpUri": SARIF_HELP_URI_BASE.format(id=eid),
            "defaultConfiguration": {
                "level": level_map.get(urgency, "warning"),
            },
            "properties": {
                "tags": [
                    entry.get("section", "general"),
                    f"urgency:{urgency.lower()}",
                    f"blast-radius:{entry.get('blast_radius', 'single-resource')}",
                ] + [f"cis:{c}" for c in (entry.get("cis") or [])],
                "precision": "high",
                "problem.severity": urgency.lower(),
                "security-severity": severity_map.get(urgency, "5.0"),
            },
        })

    results = []
    for f in findings:
        result = {
            "ruleId": f["id"],
            "ruleIndex": rule_index.get(f["id"], 0),
            "level": "warning",
            "message": {"text": f"Finding {f['id']} on {f['resource'] or 'file'}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": max(f["line"], 1)},
                    }
                }
            ],
            "partialFingerprints": _sarif_fingerprint(f),
        }
        if f["id"] in rule_index:
            result["level"] = rules[rule_index[f["id"]]]["defaultConfiguration"]["level"]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tf-analyze",
                        "version": "1.2.0",
                        "informationUri": "https://github.com/ChrisAdkin8/tf-analyze",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


# ---- adversarial scenario narratives ------------------------------------

_ATTACK_NARRATIVES: dict[str, str] = {
    "SEC-AWS-SSRF-001": (
        "An attacker exploiting a Server-Side Request Forgery (SSRF) vulnerability in any "
        "application running on {resource} can query the EC2 metadata endpoint "
        "(http://169.254.169.254/) and retrieve temporary IAM credentials without "
        "authentication — IMDSv1 requires no session token. "
        "This was the exact attack vector in the 2019 Capital One breach, where a WAF "
        "misconfiguration allowed an SSRF that exfiltrated 100M customer records via the "
        "instance's over-privileged role. "
        "Enforcing IMDSv2 (http_tokens = \"required\") breaks the chain because the "
        "attacker's request must first complete a PUT handshake that a server-side forged "
        "request cannot perform."
    ),
    "SEC-AWS-IAM-001": (
        "A wildcard Resource in the IAM policy attached to {resource} grants the declared "
        "actions against every AWS resource in the account — any credential theft, role "
        "assumption, or confused-deputy exploit immediately yields account-wide blast radius. "
        "In the 2019 Capital One breach a broad S3-read role attached to an EC2 instance "
        "was the reason 100M records could be exfiltrated after SSRF retrieved the role's "
        "STS token. "
        "Scope the Resource ARN to the specific bucket, table, or secret the workload needs."
    ),
    "SEC-AWS-IAM-002": (
        "{resource} grants the AdministratorAccess policy or equivalent wildcard, giving any "
        "principal bound to it full control over every AWS service and resource in the account. "
        "Compromise of a single workload using this role — via SSRF, code injection, or supply "
        "chain attack — yields immediate account takeover with no further privilege escalation "
        "required. "
        "Replace with a least-privilege policy scoped to the exact API calls and resource ARNs "
        "the workload uses."
    ),
    "SEC-GCP-IAM-001": (
        "The broad project-level role granted by {resource} gives any principal bound to it "
        "control over every resource in the GCP project — compute, storage, secrets, and IAM "
        "itself. "
        "An attacker who compromises a single workload service account inheriting this binding "
        "can pivot to exfiltrate Cloud SQL databases, read Secret Manager secrets, and create "
        "persistent backdoor service accounts, as demonstrated in multiple GCP supply-chain "
        "incidents. "
        "Replace with the narrowest resource-level role covering only the API surfaces the "
        "workload calls."
    ),
    "SEC-AWS-S3-001": (
        "Unencrypted data in {resource} is readable in plaintext by any AWS principal with "
        "s3:GetObject, including anyone who obtains temporary credentials via SSRF, stolen "
        "access keys, or a confused-deputy attack on an over-permissioned role. "
        "The 2017 Verizon and 2017 Accenture incidents both involved S3 buckets with sensitive "
        "data exposed without encryption, compounding the impact of misconfigured access controls. "
        "Apply SSE-KMS with a customer-managed key so data at rest requires key access in "
        "addition to bucket permissions."
    ),
    "SEC-AWS-SG-001": (
        "The security group {resource} accepts ingress from 0.0.0.0/0, making every instance "
        "in the group reachable from the public internet on the allowed port. "
        "This directly expands the attack surface for brute-force, CVE exploitation, and lateral "
        "movement — the 2020 SolarWinds attacker used internet-accessible management ports on "
        "internal hosts as persistence anchors. "
        "Restrict ingress to specific CIDR ranges, or use a bastion or SSM Session Manager to "
        "eliminate the public attack surface entirely."
    ),
    "SEC-AWS-RDS-001": (
        "Setting publicly_accessible = true on {resource} assigns the database a DNS name "
        "resolvable from the internet, exposing the database port to any network adversary. "
        "Combined with weak or default credentials, this is a trivially exploited attack path — "
        "internet-scanning tools like Shodan index publicly accessible RDS endpoints within "
        "minutes of provisioning. "
        "Place the instance in private subnets and use a VPC-peered bastion or AWS Systems "
        "Manager for administrative access."
    ),
    "SEC-AWS-CLOUDTRAIL-001": (
        "A single-region CloudTrail on {resource} creates detection blind spots in every other "
        "AWS region — an attacker deliberately operates in less-monitored regions to create IAM "
        "backdoors, launch instances, or establish data exfiltration pipelines. "
        "The 2020 SolarWinds-related AWS campaign specifically leveraged regions the victim had "
        "not enabled CloudTrail in, delaying detection by weeks. "
        "Enable is_multi_region_trail = true and include_global_service_events = true to capture "
        "all IAM and STS calls regardless of region."
    ),
    "SEC-GCP-GKE-NETWORK-POLICY-001": (
        "Without a network policy on {resource}, every pod in the cluster can reach every other "
        "pod on every port — there is no namespace isolation or default-deny. "
        "An attacker who compromises one container can scan and pivot to databases, metadata "
        "servers, and control-plane endpoints without any network-layer barrier, as demonstrated "
        "in the 2020 Tesla Kubernetes cryptomining incident where lateral movement from one "
        "compromised pod was unrestricted. "
        "Enable the built-in network policy provider and deploy default-deny egress policies in "
        "every workload namespace."
    ),
    "SEC-AZURE-RBAC-001": (
        "A subscription-scoped role assignment on {resource} grants the bound principal control "
        "over every resource in the Azure subscription — VMs, storage accounts, Key Vaults, and "
        "all other services. "
        "Compromise of the assigned identity via token theft, phishing, or service principal "
        "credential leak yields immediate lateral-movement capability across the entire "
        "subscription boundary, as seen in multiple Azure post-exploitation chains. "
        "Scope the assignment to the narrowest resource group or individual resource that "
        "satisfies the use case."
    ),
    "SEC-GCP-COMPUTE-PUBLIC-IP-001": (
        "{resource} has a public IP via an access_config block, making it directly reachable "
        "from the internet and exposing any listening service to internet-scale scanners and "
        "exploit attempts. "
        "GCP instances with public IPs are routinely targeted within minutes of provisioning "
        "by automated credential-stuffing and exploitation bots, as documented in multiple GCP "
        "threat intelligence reports. "
        "Remove the access_config block and use Cloud NAT for outbound traffic; use "
        "Identity-Aware Proxy for authenticated inbound access."
    ),
    "SEC-AWS-KMS-001": (
        "KMS key rotation is disabled on {resource}, meaning that if the key material is ever "
        "compromised — via AWS account takeover, insider threat, or KMS API misuse — the "
        "compromise is permanent with no rotation event to remediate it. "
        "CIS AWS 2.8 requires annual key rotation as a compensating control for key exposure; "
        "disabling rotation violates PCI-DSS 3.6.4 for cryptographic keys protecting cardholder "
        "data. "
        "Enable enable_key_rotation = true; AWS rotates automatically and retains old material "
        "for decryption of previously encrypted data."
    ),
    "SEC-GCP-COMPUTE-SA-001": (
        "{resource} uses the default Compute Engine service account, which holds roles/editor "
        "project-wide — any workload code or attacker who gains code execution on this VM can "
        "read every bucket, modify every Cloud SQL database, and impersonate other service "
        "accounts. "
        "The default SA pattern was the root cause in several GCP privilege-escalation chains "
        "documented by Palo Alto Unit 42, where container escape led to project-wide compromise "
        "via the VM's inherited credentials. "
        "Bind a dedicated, narrowly scoped service account to every Compute instance."
    ),
    "SEC-HARDCODED-SECRET-001": (
        "A hardcoded credential in {file} is stored in version control history permanently — "
        "git filter-repo is required to fully purge it, and any fork or clone made before "
        "remediation retains the value. "
        "The 2022 Samsung source code leak and the 2021 Twitch leak both exposed hardcoded API "
        "keys that were immediately weaponized by threat actors monitoring public repos with "
        "automated credential-scanning tools. "
        "Rotate the credential immediately, replace it with a Secrets Manager or Vault reference, "
        "and add the pattern to a pre-commit hook to prevent recurrence."
    ),
    "SEC-GCP-SQL-PUBLIC-001": (
        "{resource} has ipv4_enabled = true, assigning the Cloud SQL instance a public IP "
        "reachable from the internet — even with authorized_networks set, a single misconfigured "
        "network rule or future change exposes the database to direct attack. "
        "Internet-exposed Cloud SQL instances are routinely targeted by automated "
        "credential-stuffing attacks, and any SQL injection in the connected application can be "
        "exploited without traversing VPC boundaries. "
        "Set ipv4_enabled = false and use Private Service Connect or private IP allocation for "
        "all database connectivity."
    ),
}


def _narrative_for_finding(
    rule_id: str,
    resource: str = "",
    file: str = "",
) -> str | None:
    """Return a formatted attack narrative for a rule ID, or None if unavailable."""
    template = _ATTACK_NARRATIVES.get(rule_id)
    if template is None:
        return None
    return template.format(
        resource=resource or rule_id,
        file=file or "unknown file",
    )


# ---- HTML output ---------------------------------------------------------

def _render_executive_view(
    findings: list[dict],
    entries: list[dict],
    graph: dict | None,
) -> str:
    """Render the Executive View tab body — findings reorganised by attack stage."""
    entry_map = {e["id"]: e for e in entries}

    # Build node membership sets from graph
    internet_set: set[str] = set()
    crown_set: set[str] = set()
    iam_net_set: set[str] = set()
    if graph:
        for n in graph.get("nodes", []):
            nid = n["id"]
            if n.get("internet_reachable"):
                internet_set.add(nid)
            if n.get("is_crown_jewel"):
                crown_set.add(nid)
            if n.get("type") in ("iam", "network"):
                iam_net_set.add(nid)

    # Classify each finding into a stage
    entry_points: list[dict] = []
    lateral_movement: list[dict] = []
    crown_jewels: list[dict] = []
    blind_spots: list[dict] = []
    for f in findings:
        res = f.get("resource", "")
        entry = entry_map.get(f["id"], {})
        section = entry.get("section", "")
        if section == "ops":
            blind_spots.append(f)
        elif res in crown_set:
            crown_jewels.append(f)
        elif res in internet_set:
            entry_points.append(f)
        elif res in iam_net_set:
            lateral_movement.append(f)
        else:
            blind_spots.append(f)  # unclassified → blind spots bucket

    def _stage_html(title: str, colour: str, prose: str, stage_findings: list[dict]) -> str:
        if not stage_findings:
            return f"<div style='margin-bottom:1.4em'><h3 style='color:{colour};margin-bottom:.3em'>{title}</h3><p style='color:#888;font-size:13px'>No findings in this stage.</p></div>"
        rows = []
        for f in stage_findings:
            entry = entry_map.get(f["id"], {})
            urgency = _effective_urgency(f, entry)
            urg_colour = {"CRITICAL": "#7b0000", "HIGH": "#b02a2a", "MEDIUM": "#b07800", "LOW": "#5a7a00"}.get(urgency, "#555")
            rows.append(
                f"<li style='margin:.3em 0;font-size:13px'>"
                f"<span style='background:{urg_colour};color:#fff;padding:1px 7px;border-radius:3px;"
                f"font-size:11px;font-weight:700;margin-right:.5em'>{urgency}</span>"
                f"<b>{f['id']}</b> — {entry.get('title','')}"
                f"<span style='color:#888;margin-left:.5em'>{f.get('resource','')}</span>"
                f"<span style='color:#aaa;font-size:11px;margin-left:.5em'>{f.get('file','').rsplit('/',2)[-1]}:{f.get('line','')}</span>"
                f"</li>"
            )
        rows_html = "\n".join(rows)
        return (
            f"<div style='margin-bottom:1.8em'>"
            f"<h3 style='color:{colour};margin:.6em 0 .3em'>{title} "
            f"<span style='font-size:13px;font-weight:400;color:#666'>({len(stage_findings)} finding{'s' if len(stage_findings)!=1 else ''})</span></h3>"
            f"<p style='color:#555;font-size:13px;font-style:italic;margin-bottom:.6em'>{prose}</p>"
            f"<ul style='list-style:none;padding:0;margin:0'>{rows_html}</ul>"
            f"</div>"
        )

    cp_note = ""
    if graph and graph.get("critical_path"):
        path = graph["critical_path"]
        cp_note = (
            f"<div style='background:#fff3f3;border-left:4px solid #c0392b;padding:.7em 1em;"
            f"border-radius:0 6px 6px 0;margin-bottom:1.4em;font-size:13px'>"
            f"<b style='color:#c0392b'>Critical Attack Path detected</b> — "
            f"the shortest route from the internet to a crown jewel passes through "
            f"<b>{len(path)}</b> resource{'s' if len(path)!=1 else ''}: "
            f"{' → '.join(f'<code>{r}</code>' for r in path)}. "
            f"Findings on these resources are promoted one urgency tier."
            f"</div>"
        )

    stage1 = _stage_html(
        "&#9889; Stage 1 — Entry Points", "#d35400",
        "Internet-reachable resources with active findings. These are where an attacker gains initial access.",
        entry_points,
    )
    stage2 = _stage_html(
        "&#8596; Stage 2 — Lateral Movement", "#6c5ce7",
        "IAM roles, policies, and network resources with findings. A foothold in Stage 1 can pivot here.",
        lateral_movement,
    )
    stage3 = _stage_html(
        "&#128142; Stage 3 — Crown Jewels at Risk", "#6b0000",
        "Databases, secret stores, and encryption keys with findings. These are the targets.",
        crown_jewels,
    )
    stage4 = _stage_html(
        "&#128263; Stage 4 — Blind Spots", "#555",
        "Logging, monitoring, and operational findings. An attacker exploiting earlier stages would likely go undetected.",
        blind_spots,
    )

    return cp_note + stage1 + stage2 + stage3 + stage4


# ---- Feature 2: Safe-to-Fix Disruption Classification ------------------

_VALID_FIX_DISRUPTIONS = {"none", "plan_required", "forces_replacement"}

_FIX_DISRUPTION_LABELS = {
    "none": ("&#9989; Non-disruptive", "#27ae60"),
    "plan_required": ("&#9888;&#65039; Plan required", "#c27a00"),
    "forces_replacement": ("&#128293; Forces replacement", "#b02a2a"),
}


def _disruption_badge(disruption: str) -> str:
    label, color = _FIX_DISRUPTION_LABELS.get(disruption, ("", ""))
    if not label:
        return ""
    return (
        f"<span style='background:{color};color:#fff;padding:1px 7px;"
        f"border-radius:3px;font-size:11px;font-weight:600;"
        f"margin-left:6px'>{label}</span>"
    )


# ---- Feature 3: Compliance Gap Report ----------------------------------

_CIS_FRAMEWORK_PREFIXES = [
    ("SEC-AWS", "CIS AWS Foundations Benchmark v3.0"),
    ("ROB-AWS", "CIS AWS Foundations Benchmark v3.0"),
    ("SEC-GCP", "CIS GCP Foundations Benchmark v4.0"),
    ("ROB-GCP", "CIS GCP Foundations Benchmark v4.0"),
    ("SEC-AZURE", "CIS Azure Foundations Benchmark v2.0"),
    ("ROB-AZURE", "CIS Azure Foundations Benchmark v2.0"),
]


def _infer_cis_framework(rule_id: str) -> str:
    for prefix, fw in _CIS_FRAMEWORK_PREFIXES:
        if rule_id.startswith(prefix):
            return fw
    return "Other"


def _compliance_gap_report(
    findings: list[dict],
    entries: list[dict],
    framework: str = "cis",
) -> dict:
    """Map compliance controls against fired findings; return {framework: [control_dicts]}.

    Each control dict: {control, rules, status ('PASS'|'FAIL'), failed_rules}.
    Controls with no catalogue coverage are omitted (NOT-ASSESSABLE).

    framework: 'cis' (default), 'pci_dss', 'soc2', or 'all' (combines all three).
    """
    fired_ids = {f["id"] for f in findings}
    control_map: dict[str, dict] = {}

    want_cis    = framework in ("cis", "all")
    want_pci    = framework in ("pci_dss", "all")
    want_soc2   = framework in ("soc2", "all")

    for entry in entries:
        eid = entry.get("id", "")

        if want_cis:
            cis_list = entry.get("cis", [])
            if not isinstance(cis_list, list):
                cis_list = [cis_list] if cis_list else []
            fw_name = _infer_cis_framework(eid)
            for ctrl in cis_list:
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

        if want_pci:
            pci_list = entry.get("pci_dss", [])
            if not isinstance(pci_list, list):
                pci_list = [pci_list] if pci_list else []
            for ctrl in pci_list:
                fw_name = "PCI-DSS v4.0"
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

        if want_soc2:
            soc2_list = entry.get("soc2_cc", [])
            if not isinstance(soc2_list, list):
                soc2_list = [soc2_list] if soc2_list else []
            for ctrl in soc2_list:
                fw_name = "SOC2 Trust Services Criteria"
                key = f"{fw_name}::{ctrl}"
                if key not in control_map:
                    control_map[key] = {
                        "framework": fw_name, "control": str(ctrl),
                        "rules": [], "failed_rules": [], "status": "PASS",
                    }
                control_map[key]["rules"].append(eid)

    for item in control_map.values():
        failed = [r for r in item["rules"] if r in fired_ids]
        item["failed_rules"] = failed
        item["status"] = "FAIL" if failed else "PASS"

    by_fw: dict[str, list[dict]] = {}
    for item in control_map.values():
        by_fw.setdefault(item["framework"], []).append(item)

    def _ctrl_sort_key(c: dict) -> list:
        parts = re.split(r'[.\-]', c["control"])
        return [int(x) if x.isdigit() else x for x in parts]

    for fw in by_fw:
        by_fw[fw].sort(key=_ctrl_sort_key)

    return by_fw


def _render_compliance_text(by_fw: dict) -> str:
    lines: list[str] = ["## Compliance Gap Report", ""]
    for fw in sorted(by_fw):
        controls = by_fw[fw]
        total = len(controls)
        passed = sum(1 for c in controls if c["status"] == "PASS")
        failed = total - passed
        lines.append(f"### {fw}")
        lines.append(f"Coverage: {passed}/{total} PASS, {failed} FAIL")
        lines.append("")
        lines.append(f"{'Control':<14}{'Status':<10}Rules")
        lines.append("-" * 70)
        for ctrl in controls:
            rules_str = ", ".join(ctrl["rules"])
            fail_str = (
                f"  [FAIL: {', '.join(ctrl['failed_rules'])}]"
                if ctrl["failed_rules"] else ""
            )
            lines.append(f"{ctrl['control']:<14}{ctrl['status']:<10}{rules_str}{fail_str}")
        lines.append("")
    return "\n".join(lines)


def _render_compliance_html(by_fw: dict) -> str:
    sections: list[str] = []
    for fw in sorted(by_fw):
        controls = by_fw[fw]
        total = len(controls)
        passed = sum(1 for c in controls if c["status"] == "PASS")
        failed = total - passed
        pct = int(100 * passed / total) if total else 0
        bar_color = "#27ae60" if pct >= 80 else ("#c27a00" if pct >= 50 else "#b02a2a")
        rows: list[str] = []
        for ctrl in controls:
            sbadge = (
                "<span style='background:#27ae60;color:#fff;padding:1px 8px;"
                "border-radius:3px;font-size:11px;font-weight:600'>PASS</span>"
                if ctrl["status"] == "PASS" else
                "<span style='background:#b02a2a;color:#fff;padding:1px 8px;"
                "border-radius:3px;font-size:11px;font-weight:600'>FAIL</span>"
            )
            rules_html = ", ".join(f"<code>{r}</code>" for r in ctrl["rules"])
            fail_html = ""
            if ctrl["failed_rules"]:
                fail_html = (
                    " <span style='color:#b02a2a'>("
                    + ", ".join(f"<code>{r}</code>" for r in ctrl["failed_rules"])
                    + " fired)</span>"
                )
            rows.append(
                f"<tr><td style='font-family:monospace'>{ctrl['control']}</td>"
                f"<td>{sbadge}</td>"
                f"<td>{rules_html}{fail_html}</td></tr>"
            )
        sections.append(
            f"<h3>{fw}</h3>"
            f"<p style='color:#555;font-size:13px'>"
            f"{passed}/{total} controls PASS ({pct}%) — {failed} FAIL</p>"
            f"<div style='background:#eee;border-radius:4px;height:8px;margin-bottom:.8em'>"
            f"<div style='background:{bar_color};width:{pct}%;height:8px;border-radius:4px'>"
            f"</div></div>"
            f"<table class='locs'>"
            f"<thead><tr><th>Control</th><th>Status</th><th>Mapped Rules</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )
    return (
        "<h2 style='margin-top:.5em'>CIS Compliance Gap Report</h2>"
        "<p style='color:#555;font-size:13px;margin-bottom:.8em'>"
        "Controls derived from catalogue <code>cis:</code> fields. "
        "PASS = no finding fired. FAIL = at least one finding fired. "
        "Controls without catalogue coverage are NOT-ASSESSABLE and omitted.</p>"
        + "".join(sections)
    )


def _compliance_to_oscal(by_fw: dict, target_dir: str = "") -> dict:
    """Produce a minimal OSCAL Assessment Results JSON structure."""
    import datetime as _dt
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings_oscal: list[dict] = []
    for fw, controls in sorted(by_fw.items()):
        for ctrl in controls:
            findings_oscal.append({
                "control-id": ctrl["control"],
                "framework": fw,
                "status": ctrl["status"].lower(),
                "related-observations": [
                    {"observation-uuid": r} for r in ctrl["failed_rules"]
                ],
            })
    return {
        "assessment-results": {
            "uuid": f"tf-analyze-{ts}",
            "metadata": {
                "title": "tf-analyze CIS Compliance Assessment",
                "last-modified": ts,
                "version": "1.0",
                "oscal-version": "1.1.2",
                "remarks": f"Generated by tf-analyze for target: {target_dir}",
            },
            "results": [
                {
                    "uuid": f"result-{ts}",
                    "title": f"tf-analyze scan",
                    "start": ts,
                    "findings": findings_oscal,
                }
            ],
        }
    }


# ---- Feature 1 (cont): Fix Priority HTML rendering ----------------------

def _render_fix_priority_html(scored: list[dict]) -> str:
    """Render the Fix Priority ranked table as an HTML panel."""
    if not scored:
        return (
            "<p style='color:#888;font-style:italic;padding:1em'>"
            "No attack-graph data available. Run with <code>--attack-graph</code> "
            "to enable centrality scoring.</p>"
        )
    rows = []
    for i, item in enumerate(scored, 1):
        score = item["impact"]
        score_cls = "critical" if score >= 15 else ("high" if score >= 8 else "medium")
        cp_badge = (
            "<span class='badge-cp'>CRITICAL-PATH</span>"
            if item["on_critical_path"] else ""
        )
        ir_badge = (
            "<span style='background:#d35400;color:#fff;padding:1px 6px;"
            "border-radius:3px;font-size:10px;font-weight:700;margin-left:4px'>"
            "INET-REACHABLE</span>"
            if item["internet_reachable"] else ""
        )
        rows.append(
            f"<tr>"
            f"<td style='font-weight:700;text-align:center;width:2.5em'>{i}</td>"
            f"<td><code>{item['finding_id']}</code></td>"
            f"<td><code>{item['resource']}</code>{cp_badge}{ir_badge}</td>"
            f"<td style='text-align:center'>{item['crowns_blocked']}</td>"
            f"<td style='text-align:center'>"
            f"<span class='u u-{score_cls}'>{score}</span></td>"
            f"</tr>"
        )
    return (
        "<h2 style='margin-top:.5em'>Fix Priority</h2>"
        "<p style='color:#555;font-size:13px;margin-bottom:.8em'>"
        "Findings ranked by attack-path impact. "
        "<em>Crowns Blocked</em> = crown-jewel resources (RDS, S3, KMS, Secrets Manager) "
        "that become unreachable from the internet when this finding is fixed.</p>"
        "<table class='locs'><thead><tr>"
        "<th>#</th><th>Rule</th><th>Resource</th>"
        "<th>Crowns Blocked</th><th>Score</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def to_html(
    findings: list[dict],
    entries: list[dict],
    suppressed: list[dict],
    graph: dict | None = None,
    show_fixes: bool = False,
    centrality: list[dict] | None = None,
    compliance_data: dict | None = None,
) -> str:
    """Produce a single-file HTML report, scalable to hundreds of findings.

    Groups by catalogue ID, collapsible per group.  No external CSS/JS —
    self-contained for offline review.  When `graph` is provided (from
    build_attack_graph) an interactive Attack Graph tab is included.
    """
    entry_map = {e["id"]: e for e in entries}
    by_id: dict[str, list[dict]] = {}
    for f in findings:
        by_id.setdefault(f["id"], []).append(f)
    urgency_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_ids = sorted(
        by_id.keys(),
        key=lambda i: (
            urgency_rank.get(entry_map.get(i, {}).get("default_urgency", "MEDIUM"), 2),
            -len(by_id[i]),
            i,
        ),
    )

    def _make_detail_rows(eid: str, urgency: str, fs: list[dict]) -> str:
        entry_local = entry_map.get(eid, {})
        parts = []
        for f in fs:
            cp_badge = "<span class='badge-cp'>CRITICAL-PATH</span>" if f.get("on_critical_path") else ""
            parts.append(
                f"<tr><td><code>{f.get('file','')}</code>:{f.get('line','')}</td>"
                f"<td><code>{f.get('resource','')}</code>{cp_badge}</td></tr>"
            )
            if urgency in ("HIGH", "CRITICAL"):
                narrative = _narrative_for_finding(
                    eid, f.get("resource", ""), f.get("file", "")
                )
                if narrative:
                    parts.append(
                        f"<tr><td colspan='2'>"
                        f"<p class='narrative'>{narrative}</p>"
                        f"</td></tr>"
                    )
            if show_fixes and entry_local.get("fix_hcl"):
                hcl = entry_local["fix_hcl"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                disruption = entry_local.get("fix_disruption", "")
                d_badge = _disruption_badge(disruption)
                d_note = entry_local.get("fix_disruption_note", "")
                d_note_html = f"<p style='color:#888;font-size:11px;margin:.2em 0 .4em'>{d_note}</p>" if d_note else ""
                parts.append(
                    f"<tr><td colspan='2'>"
                    f"<details><summary style='cursor:pointer;color:#27ae60;font-size:12px;margin-top:.4em'>&#9654; Suggested fix{d_badge}</summary>"
                    f"{d_note_html}"
                    f"<pre class='fix-hcl'>{hcl}</pre></details>"
                    f"</td></tr>"
                )
        return "".join(parts)

    rows = []
    for eid in sorted_ids:
        entry = entry_map.get(eid, {})
        fs = by_id[eid]
        # Use effective urgency: per-finding reachability-adjusted urgency if available,
        # else catalogue default. Take the highest urgency among all findings for the summary badge.
        urgency = entry.get("default_urgency", "MEDIUM")
        eff_urgencies = [_effective_urgency(f, entry) for f in fs]
        display_urgency = max(eff_urgencies, key=lambda u: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(u, 2)) if eff_urgencies else urgency
        title = entry.get("title", eid)
        detail_rows = _make_detail_rows(eid, display_urgency, fs)
        rows.append(
            f"<details><summary><span class='u u-{display_urgency.lower()}'>{display_urgency}</span> "
            f"<b>{eid}</b> — {title} ({len(fs)})</summary>"
            f"<table class='locs'><thead><tr><th>Location</th><th>Resource</th></tr></thead>"
            f"<tbody>{detail_rows}</tbody></table></details>"
        )

    suppressed_section = ""
    if suppressed:
        sups = "".join(
            f"<li><code>{s['id']}</code> {s.get('file','')}:{s.get('line','')} — "
            f"{s.get('suppression_reason','')}</li>"
            for s in suppressed
        )
        suppressed_section = f"<h2>Suppressed ({len(suppressed)})</h2><ul>{sups}</ul>"

    findings_panel = f"{''.join(rows)}\n{suppressed_section}"

    tab_bar = ""
    tab_js = ""
    graph_panel_html = ""
    graph_tab_style = ""
    exec_panel_html = ""
    fixpri_panel_html = ""
    compliance_panel_html = ""
    if graph is not None:
        exec_content = _render_executive_view(findings, entries, graph)
        exec_panel_html = f"<div id='tp-exec' class='tab-panel' style='display:none;padding:1em'>{exec_content}</div>"
        fp_btn = (
            "<button class='tab-btn' onclick='showTab(\"fixpri\",this)'>"
            "&#127381; Fix Priority</button>"
            if centrality is not None else ""
        )
        comp_btn = (
            "<button class='tab-btn' onclick='showTab(\"compliance\",this)'>"
            "&#9989; Compliance</button>"
            if compliance_data is not None else ""
        )
        tab_bar = (
            "<div class='tab-bar'>"
            "<button class='tab-btn active' onclick='showTab(\"findings\",this)'>Findings</button>"
            "<button class='tab-btn' onclick='showTab(\"graph\",this)'>&#128200; Attack Graph</button>"
            "<button class='tab-btn' onclick='showTab(\"exec\",this)'>&#127919; Executive View</button>"
            f"{fp_btn}{comp_btn}"
            "</div>"
        )
        graph_tab_style = "display:none"
        graph_panel_html = _render_graph_html(graph)
        tab_js = (
            "<script>"
            "function showTab(name,btn){"
            "document.querySelectorAll('.tab-panel').forEach(function(p){p.style.display='none';});"
            "document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});"
            "document.getElementById('tp-'+name).style.display='';"
            "btn.classList.add('active');}"
            "</script>"
        )
        fixpri_panel_html = (
            f"<div id='tp-fixpri' class='tab-panel' style='display:none;padding:1em'>"
            f"{_render_fix_priority_html(centrality)}"
            f"</div>"
            if centrality is not None else ""
        )
        compliance_panel_html = (
            f"<div id='tp-compliance' class='tab-panel' style='display:none;padding:1em'>"
            f"{_render_compliance_html(compliance_data)}"
            f"</div>"
            if compliance_data is not None else ""
        )

    if compliance_data is not None and graph is None:
        comp_btn = (
            "<button class='tab-btn' onclick='showTab(\"compliance\",this)'>"
            "&#9989; Compliance</button>"
        )
        tab_bar = (
            "<div class='tab-bar'>"
            "<button class='tab-btn active' onclick='showTab(\"findings\",this)'>Findings</button>"
            f"{comp_btn}"
            "</div>"
        )
        compliance_panel_html = (
            f"<div id='tp-compliance' class='tab-panel' style='display:none;padding:1em'>"
            f"{_render_compliance_html(compliance_data)}"
            f"</div>"
        )
        tab_js = (
            "<script>"
            "function showTab(name,btn){"
            "document.querySelectorAll('.tab-panel').forEach(function(p){p.style.display='none';});"
            "document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});"
            "document.getElementById('tp-'+name).style.display='';"
            "btn.classList.add('active');}"
            "</script>"
        )
        fixpri_panel_html = ""
        exec_panel_html = ""
        graph_tab_style = "display:none"
        graph_panel_html = ""

    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>tf-analyze report</title>
<style>
body{{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em;color:#222}}
code{{font:12px/1.3 ui-monospace,monospace;background:#f4f4f4;padding:1px 4px;border-radius:3px}}
details{{border:1px solid #e0e0e0;border-radius:6px;margin:.4em 0;padding:.6em 1em;background:#fafafa}}
summary{{cursor:pointer;user-select:none}}
.u{{padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600;color:#fff}}
.u-critical{{background:#7a0b0b}} .u-high{{background:#b02a2a}} .u-medium{{background:#c27a00}} .u-low{{background:#5a7b33}} .u-info{{background:#4a6a8a}}
.badge-cp{{background:#c0392b;color:#fff;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;margin-left:4px;vertical-align:middle}}
table.locs{{border-collapse:collapse;margin-top:.5em;width:100%;font-size:13px}}
table.locs th,table.locs td{{text-align:left;padding:.3em .5em;border-bottom:1px solid #eee}}
h1{{margin:0 0 .2em}} .meta{{color:#666;margin-bottom:1em}}
p.narrative{{font-size:12px;color:#555;border-left:3px solid #b02a2a;padding:.3em .7em;margin:.4em 0;font-style:italic;background:#fff8f8;border-radius:0 4px 4px 0}}
.tab-bar{{border-bottom:2px solid #e0e0e0;margin-bottom:1em}}
.tab-btn{{background:none;border:none;padding:.45em 1.4em;cursor:pointer;font-size:13px;border-bottom:3px solid transparent;margin-bottom:-2px;color:#555;font-weight:500}}
.tab-btn.active{{border-bottom-color:#2980b9;color:#1a1a1a;font-weight:600}}
.tab-btn:hover{{color:#1a1a1a}}
pre.fix-hcl{{background:#1a1a2e;color:#a8d8a8;padding:.8em 1em;border-radius:4px;font-size:12px;overflow-x:auto;margin:.5em 0;border-left:3px solid #27ae60}}
</style></head><body>
<h1>tf-analyze report</h1>
<div class='meta'>{len(findings)} findings across {len(by_id)} rules.</div>
{tab_bar}
<div id='tp-findings' class='tab-panel'>
{findings_panel}
</div>
<div id='tp-graph' class='tab-panel' style='{graph_tab_style}'>
{graph_panel_html}
</div>
{exec_panel_html}
{fixpri_panel_html}
{compliance_panel_html}
{tab_js}
</body></html>
"""


# ---- verify-fixed mode --------------------------------------------------

_FINDING_ROW_RE = re.compile(
    r'^\|\s*(?P<id>[A-Z]{2,4}(?:-[A-Z]+)+-\d{3})'
    r'(?:#\d+)?\s*\|'        # optional instance number
    r'(?P<middle>.*?)\|'      # skip urgency column(s)
    r'\s*`?(?P<file>[\w./-]+\.tf)`?'
    r'[:\s]*(?P<line>\d+)?'
    r'.*\|',
    re.MULTILINE,
)


def parse_markdown_report(path: Path) -> list[dict]:
    """Extract (id, file, line, resource) rows from a prior markdown report.

    The report template uses a findings table with at least these columns:
    | ID | urgency | file:line | resource | ... |

    This is intentionally tolerant — any row containing a catalogue-shaped ID
    followed by a `.tf` path is captured; delta sections ("Resolved since…")
    are skipped via section-heading tracking.
    """
    text = path.read_text()
    rows = []
    # Skip rows inside "## Resolved" or "Resolved since" sections
    current_section = ""
    in_resolved = False
    for line in text.splitlines():
        if line.startswith("#"):
            current_section = line.lower()
            in_resolved = "resolved" in current_section
            continue
        if in_resolved:
            continue
        m = _FINDING_ROW_RE.match(line)
        if not m:
            continue
        rows.append({
            "id": m.group("id"),
            "file": m.group("file"),
            "line": int(m.group("line")) if m.group("line") else 0,
            "resource": "",
        })
    return rows


def reprobe_finding(finding: dict, catalog_by_id: dict,
                    all_files_text: dict) -> str:
    """Return one of: STILL-PRESENT, RESOLVED, MOVED, STALE-LOCATION, AMBIGUOUS.

    Strategy: re-run just this catalogue entry against the named file (or all
    files, for corpus-level finders). If the pattern fires at the same line ±3,
    STILL-PRESENT. If it fires in a different file, MOVED. If it doesn't fire
    anywhere, RESOLVED. If the file is gone, STALE-LOCATION.
    """
    entry = catalog_by_id.get(finding["id"])
    if not entry:
        return "AMBIGUOUS"
    target_file = Path(finding["file"])
    if not target_file.exists() or str(target_file) not in {str(p) for p in all_files_text}:
        # corpus-level finders may still fire if the file moved
        pass

    # Re-run detection entry against every loaded file (cheap — one entry).
    hits = []
    for fp, text in all_files_text.items():
        hits.extend(detect_in_file(fp, text, [entry]))
    hits.extend(detect_corpus(Path("."), all_files_text, [entry]))

    same_file = [h for h in hits if str(h.get("file", "")) == str(target_file)]
    if same_file:
        # Within 3 lines of the original?
        if any(abs(h["line"] - finding["line"]) <= 3 for h in same_file):
            return "STILL-PRESENT"
        return "MOVED"
    if hits:
        return "MOVED"
    if not target_file.exists():
        return "STALE-LOCATION"
    return "RESOLVED"


def verify_fixed(prior_report: Path, target: Path, all_files_text: dict,
                 entries: list[dict]) -> dict:
    """Parse prior report, re-probe each finding, return a verification dict."""
    prior_findings = parse_markdown_report(prior_report)
    catalog_by_id = {e["id"]: e for e in entries}
    results: dict[str, list[dict]] = {
        "STILL-PRESENT": [],
        "RESOLVED": [],
        "MOVED": [],
        "STALE-LOCATION": [],
        "AMBIGUOUS": [],
    }
    for f in prior_findings:
        state = reprobe_finding(f, catalog_by_id, all_files_text)
        results[state].append(f)
    return {
        "prior_report": str(prior_report),
        "total_prior": len(prior_findings),
        "results": results,
    }


def write_verification_report(verify: dict, out_path: Path) -> None:
    lines = [
        "# Terraform Code Analysis — Verification Report",
        "",
        f"**Prior report:** `{verify['prior_report']}`",
        f"**Total prior findings:** {verify['total_prior']}",
        "",
        "## Summary",
        "",
        "| State | Count |",
        "|---|---|",
    ]
    for state, rows in verify["results"].items():
        lines.append(f"| {state} | {len(rows)} |")
    lines.append("")
    for state, rows in verify["results"].items():
        if not rows:
            continue
        lines.append(f"## {state}")
        lines.append("")
        lines.append("| ID | File | Line |")
        lines.append("|---|---|---|")
        for r in rows:
            lines.append(f"| {r['id']} | `{r['file']}` | {r.get('line','')} |")
        lines.append("")
    out_path.write_text("\n".join(lines))


# ---- Auto-stub generation -----------------------------------------------

def generate_stub(finding_id: str, finding: dict, stub_dir: Path) -> Path | None:
    """Scaffold a catalogue YAML stub for an exploratory finding."""
    safe_id = re.sub(r'[^A-Za-z0-9_-]', '_', finding_id)
    stub_path = stub_dir / f"{safe_id}.yaml"
    if stub_path.exists():
        return None  # don't overwrite existing

    resource = finding.get("resource", "")
    resource_type = resource.split(".")[0] if "." in resource else ""

    content = f"""id: {safe_id}
title: "TODO: describe finding"
section: robustness
default_urgency: MEDIUM
blast_radius: single-resource
status: stub
patterns:
  - kind: grep
    file_glob: "**/*.tf"
    regex: 'TODO: add detection pattern'
    description: TODO
recommendation: |
  TODO: describe recommended fix.
verification: |
  TODO: describe how to verify the fix.
"""
    stub_path.write_text(content)
    return stub_path


def generate_tftest(
    findings: list[dict],
    entries: list[dict],
    out_dir: "Path",
) -> list["Path"]:
    """For each finding whose catalogue entry has a `test_template` field,
    render and write a .tftest.hcl assertion file to out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    entry_map = {e["id"]: e for e in entries}
    written: list[Path] = []
    seen: set[str] = set()
    for f in findings:
        entry = entry_map.get(f["id"])
        if not entry:
            continue
        tmpl = entry.get("test_template")
        if not tmpl:
            continue
        resource = f.get("resource", "unknown")
        safe = re.sub(r"[^a-zA-Z0-9_]", "_", resource)
        key = f"{f['id']}_{safe}"
        if key in seen:
            continue
        seen.add(key)
        rendered = tmpl.replace("{resource}", resource).replace("{rule_id}", f["id"])
        out_path = out_dir / f"{key}.tftest.hcl"
        out_path.write_text(rendered)
        written.append(out_path)
    return written


# ---- Diff-mode file filtering -------------------------------------------

def _auto_detect_base_branch(target: Path) -> str:
    """Return 'main' or 'master' depending on which exists, else 'main'."""
    for branch in ("main", "master"):
        result = subprocess.run(
            ["git", "rev-parse", "--verify", branch],
            capture_output=True, cwd=str(target),
        )
        if result.returncode == 0:
            return branch
    return "main"


def find_latest_prior(reports_dir: Path, suffix: str = ".md") -> Path | None:
    """Return the most recent tf-analysis-YYYY-MM-DD<suffix> under reports_dir."""
    if not reports_dir.is_dir():
        return None
    candidates = sorted(
        reports_dir.glob(f"tf-analysis-*{suffix}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def get_diff_files(target: Path, diff_base: str) -> set[Path]:
    """Return set of .tf files changed between diff_base and HEAD."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{diff_base}...HEAD", "--", "*.tf"],
            capture_output=True,
            text=True,
            cwd=str(target),
        )
        if result.returncode != 0:
            # Fall back to diff against working tree
            result = subprocess.run(
                ["git", "diff", "--name-only", diff_base, "--", "*.tf"],
                capture_output=True,
                text=True,
                cwd=str(target),
            )
        # Also include untracked .tf files
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard", "--", "*.tf"],
            capture_output=True,
            text=True,
            cwd=str(target),
        )

        files = set()
        git_root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, cwd=str(target),
        )
        git_root = Path(git_root_result.stdout.strip()) if git_root_result.returncode == 0 else target

        for line in result.stdout.strip().splitlines():
            if line:
                fp = (git_root / line).resolve()
                if fp.exists():
                    files.add(fp)
        for line in (untracked.stdout or "").strip().splitlines():
            if line:
                fp = (git_root / line).resolve()
                if fp.exists():
                    files.add(fp)
        return files
    except FileNotFoundError:
        print("WARN: git not found, falling back to full scan", file=sys.stderr)
        return set()


# ---- Suppression --------------------------------------------------------

def load_suppressions(target: Path) -> tuple[dict, dict]:
    """Load suppressions from .tf-analyze-ignore.yaml if it exists.

    Returns (active, expired) — both dicts of catalogue_id ->
    {"reason": str, "expires": str|None}. Expired suppressions are not
    silently dropped; the caller uses them to label findings that were
    previously suppressed but are now active because the date passed.
    """
    active: dict[str, dict] = {}
    expired: dict[str, dict] = {}
    ignore_file = target / ".tf-analyze-ignore.yaml"
    if not ignore_file.exists():
        # Check parent directory too (repo root)
        parent_ignore = target.parent / ".tf-analyze-ignore.yaml"
        if parent_ignore.exists():
            ignore_file = parent_ignore
        else:
            return active, expired

    try:
        data = load_yaml(ignore_file.read_text())
        for item in data.get("suppressions") or []:
            sid = item.get("id", "")
            if not sid:
                continue
            entry = {
                "reason": item.get("reason", ""),
                "expires": item.get("expires"),
            }
            expires = entry["expires"]
            if expires:
                import datetime
                try:
                    exp_date = datetime.date.fromisoformat(str(expires))
                    if exp_date < datetime.date.today():
                        expired[sid] = entry
                        continue
                except ValueError:
                    # Malformed date — surface loudly rather than silently
                    # treating the suppression as active.
                    print(
                        f"WARN: suppression {sid} has malformed "
                        f"expires={expires!r}; treating as active. "
                        f"Use ISO date YYYY-MM-DD.",
                        file=sys.stderr,
                    )
            active[sid] = entry
    except Exception as e:
        print(f"WARN: failed to load {ignore_file}: {e}", file=sys.stderr)
    return active, expired


def load_inline_suppressions(text: str) -> dict[int, set[str]]:
    """Find # tf-analyze:ignore <ID> comments and return line->set(IDs)."""
    result: dict[int, set[str]] = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = INLINE_IGNORE_RE.search(line)
        if m:
            result.setdefault(i, set()).add(m.group(1))
            # Also suppress on the next line (for comments above a block)
            result.setdefault(i + 1, set()).add(m.group(1))
    return result


def apply_suppressions(findings: list[dict], file_suppressions: dict,
                       global_suppressions: dict) -> tuple[list[dict], list[dict]]:
    """Split findings into active and suppressed lists."""
    active = []
    suppressed = []
    for f in findings:
        fid = f["id"]
        # Check global suppressions
        if fid in global_suppressions:
            f["suppression_reason"] = global_suppressions[fid].get("reason", "")
            suppressed.append(f)
            continue
        # Check inline suppressions
        fline = f.get("line", 0)
        ffile = f.get("file", "")
        inline = file_suppressions.get(ffile, {})
        if fline in inline and fid in inline[fline]:
            f["suppression_reason"] = "inline comment"
            suppressed.append(f)
            continue
        active.append(f)
    return active, suppressed


# ---- Report comparison ---------------------------------------------------

def compare_reports(current: list[dict], prior_path: Path) -> dict:
    """Compare current findings against a prior JSON report.

    Returns {resolved: [...], new: [...], unchanged: [...]}.
    """
    try:
        data = json.loads(prior_path.read_text())
        # Handle both list format and dict format
        if isinstance(data, list):
            prior_findings = data
        else:
            prior_findings = data.get("findings", [])
    except Exception as e:
        print(f"WARN: cannot load prior report {prior_path}: {e}", file=sys.stderr)
        return {"resolved": [], "new": list(current), "unchanged": []}

    prior_keys = {(f["id"], f.get("file", ""), f.get("resource", "")) for f in prior_findings}
    current_keys = {(f["id"], f.get("file", ""), f.get("resource", "")) for f in current}

    resolved = [f for f in prior_findings
                if (f["id"], f.get("file", ""), f.get("resource", "")) not in current_keys]
    new = [f for f in current
           if (f["id"], f.get("file", ""), f.get("resource", "")) not in prior_keys]
    unchanged = [f for f in current
                 if (f["id"], f.get("file", ""), f.get("resource", "")) in prior_keys]

    return {"resolved": resolved, "new": new, "unchanged": unchanged}


# ---- Catalog loading ----------------------------------------------------

_VALID_SECTIONS = {
    "security", "robustness", "dry", "style", "simplicity",
    "ops", "cicd", "module", "stack", "verification",
}
_URGENCY_TIERS: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_VALID_URGENCIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_VALID_BLAST_RADIUS = {
    "single-resource", "module", "environment", "infrastructure-wide",
}
_VALID_STATUS = {"active", "deprecated", "stub", "experimental"}
_REQUIRED_FIELDS = (
    "id", "title", "section", "default_urgency", "blast_radius",
    "patterns", "recommendation", "verification",
)


def validate_catalog_entry(data: dict, source: str) -> list[str]:
    """Return a list of human-readable schema errors. Empty list = valid.

    `source` is the catalogue YAML file path used in error messages.
    """
    errs: list[str] = []
    if not isinstance(data, dict):
        return [f"{source}: top-level YAML is not a mapping"]
    for f in _REQUIRED_FIELDS:
        if data.get(f) in (None, "", []):
            errs.append(f"{source}: missing required field '{f}'")
    section = data.get("section")
    if section is not None and section not in _VALID_SECTIONS:
        errs.append(
            f"{source}: section '{section}' not in {sorted(_VALID_SECTIONS)}"
        )
    urgency = data.get("default_urgency")
    if urgency is not None and urgency not in _VALID_URGENCIES:
        errs.append(
            f"{source}: default_urgency '{urgency}' not in "
            f"{sorted(_VALID_URGENCIES)}"
        )
    blast = data.get("blast_radius")
    if blast is not None and blast not in _VALID_BLAST_RADIUS:
        errs.append(
            f"{source}: blast_radius '{blast}' not in "
            f"{sorted(_VALID_BLAST_RADIUS)}"
        )
    status = data.get("status")
    if status is not None and status not in _VALID_STATUS:
        errs.append(
            f"{source}: status '{status}' not in {sorted(_VALID_STATUS)}"
        )
    pats = data.get("patterns")
    if isinstance(pats, list):
        for i, p in enumerate(pats):
            if not isinstance(p, dict):
                errs.append(f"{source}: patterns[{i}] is not a mapping")
                continue
            if not p.get("kind"):
                errs.append(f"{source}: patterns[{i}] missing 'kind'")
    elif pats is not None:
        errs.append(f"{source}: 'patterns' must be a list")
    narrative = data.get("narrative")
    if narrative is not None and not isinstance(narrative, str):
        errs.append(f"{source}: 'narrative' must be a string if present")
    test_template = data.get("test_template")
    if test_template is not None and not isinstance(test_template, str):
        errs.append(f"{source}: 'test_template' must be a string if present")
    fix_hcl = data.get("fix_hcl")
    if fix_hcl is not None and not isinstance(fix_hcl, str):
        errs.append(f"{source}: 'fix_hcl' must be a string if present")
    fix_disruption = data.get("fix_disruption")
    if fix_disruption is not None and fix_disruption not in _VALID_FIX_DISRUPTIONS:
        errs.append(
            f"{source}: fix_disruption '{fix_disruption}' not in "
            f"{sorted(_VALID_FIX_DISRUPTIONS)}"
        )
    fix_disruption_note = data.get("fix_disruption_note")
    if fix_disruption_note is not None and not isinstance(fix_disruption_note, str):
        errs.append(f"{source}: 'fix_disruption_note' must be a string if present")
    pci_dss = data.get("pci_dss")
    if pci_dss is not None:
        if not isinstance(pci_dss, list) or not all(isinstance(x, str) for x in pci_dss):
            errs.append(f"{source}: 'pci_dss' must be a list of strings if present")
    soc2_cc = data.get("soc2_cc")
    if soc2_cc is not None:
        if not isinstance(soc2_cc, list) or not all(isinstance(x, str) for x in soc2_cc):
            errs.append(f"{source}: 'soc2_cc' must be a list of strings if present")
    fid = data.get("id")
    fname = Path(source).stem
    if fid and fid != fname:
        errs.append(
            f"{source}: id '{fid}' does not match filename stem '{fname}'"
        )
    return errs


def _load_project_config(target: Path) -> dict:
    """Read .tf-analyze.yaml from target directory.

    Returns {} on missing file or any parse error (with a warning to stderr).
    """
    cfg_path = target / ".tf-analyze.yaml"
    if not cfg_path.exists():
        return {}
    try:
        return load_yaml(cfg_path.read_text()) or {}
    except Exception as e:
        print(f"WARN: cannot parse {cfg_path}: {e}", file=sys.stderr)
        return {}


def load_catalog(
    catalog_dir: Path,
    include_stubs: bool = False,
    strict: bool = False,
    extra_rules_dir: Path | None = None,
) -> list[dict]:
    """Load catalogue YAMLs with schema validation.

    Stubs (status: stub) are excluded by default — their patterns may be
    incomplete and would produce false positives in normal scans. Pass
    include_stubs=True only when validating that the stub itself parses.

    Validation errors print to stderr as 'ERROR:' lines and the offending
    entry is skipped. With strict=True, a single error aborts the load
    via sys.exit(2). Default is non-strict so a stale catalogue entry
    doesn't break every CI run.

    If extra_rules_dir is set and is a directory, custom rules are loaded
    from *.yaml files there. Custom rule IDs must start with 'CUSTOM-'.
    """
    entries: list[dict] = []
    error_count = 0
    for yml in sorted(catalog_dir.glob("*.yaml")):
        try:
            data = load_yaml(yml.read_text())
        except Exception as e:
            print(f"ERROR: cannot parse {yml}: {e}", file=sys.stderr)
            error_count += 1
            continue
        # Schema validation. Skip the entry if any required field is missing
        # — the alternative (loading partial entries) lets bugs hide.
        errs = validate_catalog_entry(data, str(yml))
        if errs:
            for msg in errs:
                print(f"ERROR: {msg}", file=sys.stderr)
            error_count += len(errs)
            continue
        status = data.get("status", "active")
        if status == "deprecated":
            continue
        if status == "stub" and not include_stubs:
            continue
        entries.append(data)
    if strict and error_count:
        print(
            f"FATAL: {error_count} catalogue error(s); aborting (--strict-catalog)",
            file=sys.stderr,
        )
        sys.exit(2)

    # Load custom rules from extra_rules_dir if provided
    if extra_rules_dir is not None and Path(extra_rules_dir).is_dir():
        for yml in sorted(Path(extra_rules_dir).glob("*.yaml")):
            try:
                data = load_yaml(yml.read_text())
            except Exception as e:
                print(f"ERROR: cannot parse custom rule {yml}: {e}", file=sys.stderr)
                continue
            rule_id = data.get("id", "")
            if not str(rule_id).startswith("CUSTOM-"):
                print(
                    f"WARN: custom rule {yml} has id '{rule_id}' which does not "
                    f"start with 'CUSTOM-'; skipping",
                    file=sys.stderr,
                )
                continue
            errs = validate_catalog_entry(data, str(yml))
            if errs:
                for msg in errs:
                    print(f"ERROR: {msg}", file=sys.stderr)
                continue
            status = data.get("status", "active")
            if status == "deprecated":
                continue
            if status == "stub" and not include_stubs:
                continue
            entries.append(data)

    return entries


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

_PLAN_SUPPORTED_KINDS = {
    "resource_arg",
    "resource_missing_arg",
    "resource_present",
    "hcl_attr",
    "data_source_present",
}


def _walk_plan_resources(planned: dict) -> list[dict]:
    """Flatten the plan tree into a list of resource dicts.

    Each entry has at minimum: address, type, name, values, mode.
    Modules' resources are inlined; the address keeps the
    `module.foo.bar.baz` prefix so the operator can locate the source.
    """
    out: list[dict] = []

    def walk(node: dict | None) -> None:
        if not node:
            return
        for r in node.get("resources") or []:
            if r.get("mode") == "managed" or r.get("mode") is None:
                out.append(r)
        for cm in node.get("child_modules") or []:
            walk(cm)

    walk((planned or {}).get("root_module"))
    return out


def _plan_value_at_path(values: dict, path: str):
    """Fetch a dotted path from a resolved values dict. The provider's
    JSON encoding nests blocks as lists of dicts (e.g.
    `lifecycle: [{prevent_destroy: true}]`), so we traverse list-of-dict
    by taking the first element and continuing.
    """
    cur: object = values
    for part in path.split("."):
        if isinstance(cur, list) and cur:
            cur = cur[0]
        if not isinstance(cur, dict):
            return None
        if part not in cur:
            return None
        cur = cur[part]
    return cur


def detect_in_plan(plan_json_path: Path, entries: list[dict]) -> list[dict]:
    """Re-evaluate applicable rules against `terraform show -json` output.

    Returns the same finding shape as `detect_in_file` so the SARIF /
    JSON / markdown emitters need no changes. Findings are tagged with
    `mode: plan` so reports can disambiguate plan-time vs static-time
    triggers of the same rule ID.
    """
    try:
        plan = json.loads(plan_json_path.read_text())
    except Exception as e:
        print(
            f"ERROR: cannot read plan JSON {plan_json_path}: {e}",
            file=sys.stderr,
        )
        return []
    resources = _walk_plan_resources(plan.get("planned_values") or {})
    findings: list[dict] = []
    for entry in entries:
        eid = entry["id"]
        for pat in entry.get("patterns") or []:
            kind = pat.get("kind", "")
            if kind not in _PLAN_SUPPORTED_KINDS:
                continue
            if kind == "resource_arg":
                rt = pat.get("resource")
                arg = pat.get("arg")
                regex_str = pat.get("regex")
                not_regex_str = pat.get("not_regex")
                if not (rt and arg and (regex_str or not_regex_str)):
                    continue
                regex = re.compile(regex_str) if regex_str else None
                not_regex = re.compile(not_regex_str) if not_regex_str else None
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    val = (r.get("values") or {}).get(arg)
                    if val is None:
                        continue
                    hit = False
                    if regex and regex.search(str(val)):
                        hit = True
                    if not_regex and not not_regex.search(str(val)):
                        hit = True
                    if hit:
                        findings.append({
                            "id": eid,
                            "file": "<plan>",
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": "plan",
                        })
            elif kind == "resource_missing_arg":
                rt = pat.get("resource")
                arg_path = pat.get("arg") or pat.get("nested_path")
                if not (rt and arg_path):
                    continue
                suppress_if = pat.get("suppress_if")
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    val = _plan_value_at_path(r.get("values") or {}, arg_path)
                    if val in (None, [], {}):
                        if suppress_if:
                            s_arg = suppress_if.get("arg", "")
                            s_val = suppress_if.get("equals")
                            if s_arg and s_val is not None:
                                actual = _plan_value_at_path(r.get("values") or {}, s_arg)
                                if actual is not None and str(actual).lower() == str(s_val).lower():
                                    continue
                        findings.append({
                            "id": eid,
                            "file": "<plan>",
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": "plan",
                        })
            elif kind == "resource_present":
                rt = pat.get("resource")
                if not rt:
                    continue
                for r in resources:
                    if r.get("type") == rt:
                        findings.append({
                            "id": eid,
                            "file": "<plan>",
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": "plan",
                        })
            elif kind == "data_source_present":
                dt = pat.get("data_source")
                if not dt:
                    continue
                for r in resources:
                    if r.get("type") == dt and r.get("mode") == "data":
                        findings.append({
                            "id": eid,
                            "file": "<plan>",
                            "line": 0,
                            "resource": r.get("address", f"data.{dt}.?"),
                            "mode": "plan",
                        })
            elif kind == "hcl_attr":
                rt = pat.get("resource")
                path = pat.get("path")
                not_equal = pat.get("not_equal")
                if not (rt and path):
                    continue
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    val = _plan_value_at_path(r.get("values") or {}, path)
                    if val is None:
                        continue
                    if not_equal is not None and str(val).lower() != str(not_equal).lower():
                        findings.append({
                            "id": eid,
                            "file": "<plan>",
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": "plan",
                        })
    return findings


# ---- Meta-commands ------------------------------------------------------
#
# `--list-rules`, `--explain`, `--new-rule` operate on the catalogue alone
# and exit without running a scan. They share `load_catalog`, so the same
# schema validation that surfaces broken entries on a real scan also
# surfaces them here — which is the right behaviour: if a rule is
# malformed you want to know before listing it as available.

_RULE_ID_RE = re.compile(r'^[A-Z]+(?:-[A-Z]+)+-\d{3}$')


def _cmd_list_rules(
    catalog_dir: Path, focus: str | None, include_stubs: bool
) -> None:
    """Print every catalogue ID with title + urgency, grouped by domain."""
    entries = load_catalog(catalog_dir, include_stubs=include_stubs)
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


# ---- Fleet and trend helpers --------------------------------------------

def _resolve_fleet_targets(args) -> list[Path]:
    """Collect and resolve all target directories for fleet mode."""
    targets: list[Path] = [Path(t).resolve() for t in (args.targets or [])]
    if getattr(args, "targets_file", None):
        tf_path = Path(args.targets_file)
        if tf_path.exists():
            for line in tf_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(Path(line).resolve())
    return targets


def _fleet_scan(targets: list[Path], entries: list[dict]) -> dict:
    """Scan multiple repos and cross-correlate findings.

    Returns:
        {
          "by_target": {str(target): [findings]},
          "fleet_wide": [findings with fleet_count > 1],
          "summary": {str(target): int},
        }
    """
    by_target: dict[str, list[dict]] = {}
    for target in targets:
        tf_files = [p for p in target.rglob("*.tf") if ".terraform" not in p.parts]
        all_text: dict = {}
        for fp in tf_files:
            try:
                all_text[fp] = _read_normalized(fp)
            except Exception:
                continue
        target_findings = detect_corpus(target, all_text, entries)
        for fp, text in all_text.items():
            target_findings.extend(detect_in_file(fp, text, entries))
        by_target[str(target)] = target_findings

    # Cross-correlate: same (rule_id, resource_name) across >1 target
    # Use sets so the same finding appearing multiple times in one repo is
    # only counted once per repo for cross-repo correlation purposes.
    sig_targets: dict[tuple, set[str]] = {}
    for tgt, fs in by_target.items():
        for f in fs:
            sig = (f["id"], f.get("resource", ""), f.get("file", "").rsplit("/", 1)[-1])
            sig_targets.setdefault(sig, set()).add(tgt)

    fleet_wide: list[dict] = []
    seen_fleet: set[tuple] = set()
    for tgt, fs in by_target.items():
        for f in fs:
            sig = (f["id"], f.get("resource", ""), f.get("file", "").rsplit("/", 1)[-1])
            repos = list(sig_targets.get(sig, set()))
            if len(repos) > 1 and sig not in seen_fleet:
                seen_fleet.add(sig)
                fleet_wide.append({
                    **f,
                    "fleet_count": len(repos),
                    "fleet_repos": repos,
                })

    return {
        "by_target": by_target,
        "fleet_wide": fleet_wide,
        "summary": {t: len(fs) for t, fs in by_target.items()},
    }


def _render_fleet_report(fleet_result: dict, fmt: str) -> str:
    """Render fleet scan results as markdown table or JSON."""
    if fmt == "json":
        import json as _json
        return _json.dumps(fleet_result, indent=2, default=str)

    lines: list[str] = ["# Fleet Scan Report\n"]
    lines.append("## Per-Repo Summary\n")
    lines.append("| Repository | Findings |")
    lines.append("|---|---|")
    for tgt, count in fleet_result["summary"].items():
        lines.append(f"| `{tgt}` | {count} |")

    fleet_wide = fleet_result.get("fleet_wide", [])
    lines.append(f"\n## Fleet-Wide Findings ({len(fleet_wide)} across multiple repos)\n")
    if fleet_wide:
        lines.append("| Rule | Resource | Count | Repos |")
        lines.append("|---|---|---|---|")
        for f in fleet_wide:
            repos_short = ", ".join(r.rsplit("/", 1)[-1] for r in f.get("fleet_repos", []))
            lines.append(f"| {f['id']} | `{f.get('resource','')}` | {f.get('fleet_count',0)} | {repos_short} |")
    else:
        lines.append("_No findings appear in more than one repository._")

    # Per-repo detail
    lines.append("\n## Per-Repo Findings\n")
    for tgt, fs in fleet_result["by_target"].items():
        lines.append(f"### `{tgt}` ({len(fs)} finding{'s' if len(fs) != 1 else ''})\n")
        for f in fs[:50]:  # cap at 50 per repo to keep output readable
            lines.append(f"- `{f['id']}` {f.get('file','').rsplit('/',2)[-1]}:{f.get('line','')} `{f.get('resource','')}`")
        if len(fs) > 50:
            lines.append(f"- _...and {len(fs)-50} more_")
        lines.append("")

    return "\n".join(lines)


def _trend_get_commits(target: Path, lookback_days: int) -> list[tuple[str, str]]:
    """Return (sha, date) pairs for commits touching .tf files in last N days, oldest first."""
    import subprocess as _sp
    result = _sp.run(
        ["git", "log", "--format=%H %as", f"--since={lookback_days} days ago",
         "--reverse", "--", "*.tf"],
        capture_output=True, text=True, cwd=str(target),
    )
    if result.returncode != 0:
        return []
    pairs: list[tuple[str, str]] = []
    for line in result.stdout.strip().splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2:
            pairs.append((parts[0], parts[1].strip()))
    return pairs


def _trend_tf_files_at_sha(target: Path, sha: str) -> list[str]:
    """List .tf files tracked at a given commit SHA."""
    import subprocess as _sp
    result = _sp.run(
        ["git", "ls-tree", "-r", "--name-only", sha],
        capture_output=True, text=True, cwd=str(target),
    )
    return [p for p in result.stdout.strip().splitlines() if p.endswith(".tf")]


def _trend_scan_at_sha(
    target: Path, sha: str, entries: list[dict]
) -> set[tuple[str, str, int]]:
    """Return a set of (rule_id, rel_path, line) for a commit SHA.
    Reads file content via `git show` without checkout."""
    import subprocess as _sp
    findings_set: set[tuple[str, str, int]] = set()
    for rel_path in _trend_tf_files_at_sha(target, sha):
        show = _sp.run(
            ["git", "show", f"{sha}:{rel_path}"],
            capture_output=True, text=True, cwd=str(target),
        )
        if show.returncode != 0:
            continue
        text = show.stdout
        fake_path = target / rel_path
        try:
            for f in detect_in_file(fake_path, text, entries):
                findings_set.add((f["id"], rel_path, f.get("line", 0)))
        except Exception:
            continue
    return findings_set


def run_trend(target: Path, entries: list[dict], lookback_days: int) -> list[dict]:
    """Walk git history and compute per-commit finding deltas."""
    commits = _trend_get_commits(target, lookback_days)
    if not commits:
        return []
    rows: list[dict] = []
    prev: set[tuple[str, str, int]] = set()
    for sha, date in commits:
        curr = _trend_scan_at_sha(target, sha, entries)
        new_count = len(curr - prev)
        resolved = len(prev - curr)
        rows.append({
            "date": date,
            "sha": sha[:8],
            "new": new_count,
            "resolved": resolved,
            "net": new_count - resolved,
            "total": len(curr),
        })
        prev = curr
    return rows


def _render_trend_table(rows: list[dict], fmt: str) -> str:
    """Render trend rows as markdown table or JSON."""
    if fmt == "json":
        import json as _json
        return _json.dumps(rows, indent=2)
    if not rows:
        return "_No commits touching .tf files found in the specified lookback window._"
    lines = [
        "# Risk Trend\n",
        "| Date | SHA | New | Resolved | Net | Total |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        net_str = f"+{r['net']}" if r["net"] > 0 else str(r["net"])
        lines.append(
            f"| {r['date']} | `{r['sha']}` | +{r['new']} | -{r['resolved']} | {net_str} | {r['total']} |"
        )
    # Summary line
    if rows:
        total_new = sum(r["new"] for r in rows)
        total_res = sum(r["resolved"] for r in rows)
        net = total_new - total_res
        net_str = f"+{net}" if net > 0 else str(net)
        lines.append(f"\n**{len(rows)} commits analysed. Net change: {net_str} ({total_new} introduced, {total_res} resolved).**")
    return "\n".join(lines)


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

    repo = getattr(args, "repo", None)
    pr_number = getattr(args, "pr_number", None)
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
            elif not dl.startswith("-"):
                cur_line += 1
                pos[cur_line] = position
        file_positions[fname] = pos

    # Build inline comments
    targets: list[str] = getattr(args, "targets", None) or []
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


# ---- Registry staleness (item 7) ----------------------------------------

import urllib.request as _urllib_request

_REGISTRY_SOURCE_RE = re.compile(
    r'^"?([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)"?$'
)
_MOD_VERSION_PIN_RE = re.compile(r'(?m)^\s*version\s*=\s*"([^"]+)"')


def _query_registry_latest(namespace: str, name: str, provider: str) -> str | None:
    """Return the latest published version string from the Terraform Registry.

    Returns None on any network or parse error — callers should treat None
    as "unknown" and skip the staleness check rather than erroring out.
    """
    url = f"https://registry.terraform.io/v1/modules/{namespace}/{name}/{provider}"
    try:
        req = _urllib_request.Request(url, headers={"User-Agent": "tf-analyze/1.0"})
        with _urllib_request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return data.get("version") or None
    except Exception:
        return None


def _check_module_registry_staleness(all_files_text: dict) -> list[dict]:
    """Scan module blocks for registry-style sources and compare pinned vs latest.

    Emits MOD-STALE-001 findings when the pinned version is:
      - >= 1 major version behind latest, OR
      - >= 3 minor versions behind latest (within the same major)

    Network errors are silenced — a failed registry query does not emit a finding.
    """
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()   # deduplicate per (ns, name, provider)

    for fp, text in all_files_text.items():
        for mblk in find_blocks(text, MODULE_START):
            src = block_arg_value(mblk["body"], "source")
            if not src:
                continue
            m = _REGISTRY_SOURCE_RE.match(src.strip())
            if not m:
                continue
            ns, mod_name, provider = m.group(1), m.group(2), m.group(3)
            key = (ns, mod_name, provider)
            if key in seen:
                continue
            seen.add(key)

            pin_m = _MOD_VERSION_PIN_RE.search(mblk["body"])
            pinned = pin_m.group(1) if pin_m else None
            latest = _query_registry_latest(ns, mod_name, provider)
            if not pinned or not latest:
                continue

            pinned_v = _version_tuple(pinned)
            latest_v = _version_tuple(latest)
            if not pinned_v or not latest_v or pinned_v >= latest_v:
                continue

            # Determine staleness severity
            major_behind = latest_v[0] - pinned_v[0] if len(pinned_v) >= 1 and len(latest_v) >= 1 else 0
            minor_behind = (latest_v[1] - pinned_v[1]) if (
                len(pinned_v) >= 2 and len(latest_v) >= 2 and major_behind == 0
            ) else 0

            if major_behind >= 1:
                urgency = "MEDIUM"
            elif minor_behind >= 3:
                urgency = "LOW"
            else:
                continue   # minor drift < 3 — not worth flagging

            findings.append({
                "id": "MOD-STALE-001",
                "file": str(fp),
                "line": mblk["start_line"],
                "resource": f"module.{mblk['groups'][0]}",
                "detail": (
                    f"{ns}/{mod_name}/{provider}: pinned={pinned}, "
                    f"latest={latest} ({major_behind}M/{minor_behind}m behind)"
                ),
                "_urgency_override": urgency,
            })

    return findings


# ---- Incremental scan cache --------------------------------------------

def _corpus_hash(all_files_text: dict, entries: list) -> str:
    """Stable 16-hex-char hash over all .tf file contents and catalogue rules.

    Used by the --cache path to determine whether a full re-scan is needed.
    If every file and every catalogue entry is byte-identical to the previous
    run, the cached findings are returned without re-scanning.
    """
    fh = hashlib.sha256()
    for fp_raw in sorted(all_files_text.keys(), key=str):
        fh.update(str(fp_raw).encode())
        content = all_files_text[fp_raw]
        fh.update(content.encode() if isinstance(content, str) else content)
    ch = hashlib.sha256()
    for e in sorted(entries, key=lambda x: x["id"]):
        ch.update(e["id"].encode())
        ch.update(str(e.get("patterns", ""))[:200].encode())
    return hashlib.sha256((fh.hexdigest() + ch.hexdigest()).encode()).hexdigest()[:16]


def _load_scan_cache(cache_path: Path) -> dict | None:
    """Load a scan cache file. Returns None if absent, unreadable, or wrong version."""
    try:
        with open(cache_path) as f:
            data = json.load(f)
        if data.get("version") != 1:
            return None
        return data
    except Exception:
        return None


def _save_scan_cache(cache_path: Path, corpus_hash: str, findings: list) -> None:
    """Persist findings to the scan cache file. Failure is silent — non-fatal."""
    try:
        with open(cache_path, "w") as f:
            json.dump({"version": 1, "corpus_hash": corpus_hash, "findings": findings}, f)
    except Exception:
        pass


# ---- Auto-fix helpers ---------------------------------------------------

def _fix_hcl_body(fix_hcl: str) -> str:
    """Strip outer resource declaration from fix_hcl, returning just the body."""
    m = re.match(r'^\s*resource\s+"[^"]+"\s+"[^"]+"\s*\{(.*)\}\s*$', fix_hcl, re.DOTALL)
    return m.group(1) if m else fix_hcl


def _fix_line_for_arg(fix_hcl: str, arg: str) -> str | None:
    """Extract the `arg = value` expression from a fix_hcl snippet.

    Handles single-line attributes and multi-line map literals (`arg = { ... }`).
    Returns None if arg does not appear as an assignment (use _fix_block_for_nested_arg
    for block syntax).
    """
    body = _fix_hcl_body(fix_hcl)
    start_m = re.search(rf'(?m)^\s*{re.escape(arg)}\s*=', body)
    if not start_m:
        return None
    text = body[start_m.start():]
    newline_pos = text.find('\n')
    first_line = text if newline_pos == -1 else text[:newline_pos]
    # Count unmatched opening braces on the first line — if > 0, multi-line map
    brace_depth = first_line.count('{') - first_line.count('}')
    if brace_depth <= 0:
        return first_line.strip()
    # Multi-line map literal — brace-match to find closing `}`
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
        return first_line.strip()
    # Return raw (unstripped) so _reindent_fix_snippet can use first-line base_len
    return text[:end_pos]


def _fix_block_for_nested_arg(fix_hcl: str, arg: str) -> str | None:
    """Extract the `arg { ... }` nested block from a fix_hcl snippet.

    Returns the raw block text with the leading whitespace of the first line
    intact (used by _reindent_fix_snippet to determine base indentation).
    """
    body = _fix_hcl_body(fix_hcl)
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


def _reindent_fix_snippet(raw: str, indent: str) -> list[str]:
    """Re-indent a fix snippet (single or multi-line) for insertion into a file.

    Strips the base indentation of the first line from all lines, then prepends
    `indent`. Returns a list of newline-terminated strings ready for list insertion.
    """
    lines = raw.split('\n')
    base_len = len(lines[0]) - len(lines[0].lstrip())
    base = ' ' * base_len
    result = []
    for line in lines:
        stripped = line[base_len:] if line.startswith(base) else line
        result.append(f"{indent}{stripped}\n")
    return result


def _find_block_end_in_lines(lines: list[str], start: int) -> int | None:
    """Return the 0-based index of the line containing the closing '}' of the
    block that opens at or after `start`. Handles nested braces."""
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


def _block_indent(lines: list[str], start: int, end: int) -> str:
    """Detect the indentation string used by attributes inside a resource block."""
    for i in range(start + 1, end):
        stripped = lines[i].lstrip()
        if stripped and not stripped.startswith('}') and not stripped.startswith('#'):
            return lines[i][:len(lines[i]) - len(stripped)]
    return "  "  # fallback: 2 spaces


def _handle_apply_fixes(
    args: object,
    findings: list[dict],
    entries: list[dict],
    dry_run: bool,
) -> None:
    """Apply (or preview) fix_hcl patches for every fixable finding.

    Processes findings grouped by file, in reverse line order so that
    insertions at later lines do not shift the positions of earlier ones.
    Creates .bak backups before writing when not in dry-run mode.
    """
    entry_map = {e["id"]: e for e in entries}

    # Group fixable findings by file
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        fp = f.get("file", "")
        if not fp:
            continue
        entry = entry_map.get(f["id"])
        if not entry or not entry.get("fix_hcl"):
            continue
        by_file.setdefault(fp, []).append(f)

    total_applied = 0

    for file_path in sorted(by_file):
        path = Path(file_path)
        if not path.exists():
            continue

        with open(path) as fh:
            original_lines = fh.readlines()
        modified = original_lines[:]

        # Process findings in reverse line order — insertions at later lines
        # don't affect positions of earlier ones.
        file_findings = sorted(by_file[file_path], key=lambda x: x.get("line", 0), reverse=True)

        for finding in file_findings:
            entry = entry_map.get(finding["id"])
            fix_hcl = entry.get("fix_hcl", "")
            if not fix_hcl:
                continue

            # Find the matching pattern to learn the kind and arg
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
            # 0-based index of the resource block start.
            # find_blocks' RESOURCE_START has ^\s* which can match a blank line
            # before the resource keyword, so start_line may be 1 too low. Advance
            # to the line that actually contains the opening `{`.
            start_idx = finding.get("line", 1) - 1
            while start_idx < len(modified) - 1 and '{' not in modified[start_idx]:
                start_idx += 1

            if kind == "resource_missing_arg" and arg:
                block_end = _find_block_end_in_lines(modified, start_idx)
                if block_end is None:
                    continue
                indent = _block_indent(modified, start_idx, block_end)
                raw = _fix_line_for_arg(fix_hcl, arg) or _fix_block_for_nested_arg(fix_hcl, arg)
                if not raw:
                    continue
                modified[block_end:block_end] = _reindent_fix_snippet(raw, indent)
                total_applied += 1

            elif kind in ("resource_arg", "hcl_attr"):
                # Find the line containing `arg = <wrong_value>` within the block
                block_end = _find_block_end_in_lines(modified, start_idx)
                if block_end is None:
                    continue
                fix_line = _fix_line_for_arg(fix_hcl, arg)
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
    print(f"# apply-fixes: {action} {total_applied} fix(es) across {len(by_file)} file(s)",
          file=sys.stderr)


# ---- Main ---------------------------------------------------------------

def _run_lsp_server(catalog_dir: Path, project_config: dict) -> None:
    """JSON-RPC 2.0 LSP server on stdin/stdout."""
    import json as _json

    entries = load_catalog(catalog_dir)
    id_map = {e["id"]: e for e in entries}
    _diagnostics: dict[str, list] = {}

    def _uri_to_path(uri: str) -> Path:
        return Path(uri.removeprefix("file://"))

    def _scan_uri(uri: str) -> list[dict]:
        path = _uri_to_path(uri)
        if not path.exists() or path.suffix != ".tf":
            return []
        text = path.read_text()
        target = path.parent
        all_files = {str(p): p.read_text() for p in target.glob("*.tf") if p.exists()}
        var_defaults = _extract_var_defaults_by_dir(all_files)
        return detect_in_file(path, text, entries, var_defaults.get(str(target), {}))

    def _findings_to_diagnostics(findings: list[dict]) -> list[dict]:
        sev_map = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        diags = []
        for f in findings:
            line = max(0, f["line"] - 1)
            urgency = id_map.get(f["id"], {}).get("default_urgency", "LOW")
            diags.append({
                "range": {"start": {"line": line, "character": 0},
                           "end":   {"line": line, "character": 9999}},
                "severity": sev_map.get(urgency, 3),
                "code": f["id"],
                "source": "tf-analyze",
                "message": f"{f['id']}: {id_map.get(f['id'], {}).get('title', '')}",
            })
        return diags

    def _read_message() -> dict | None:
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            ch = sys.stdin.buffer.read(1)
            if not ch:
                return None
            header += ch
        m = re.search(rb"Content-Length: (\d+)", header)
        if not m:
            return None
        length = int(m.group(1))
        body = sys.stdin.buffer.read(length)
        return _json.loads(body)

    def _send(obj: dict) -> None:
        body = _json.dumps(obj).encode()
        sys.stdout.buffer.write(
            f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        )
        sys.stdout.buffer.flush()

    def _notify(method: str, params: dict) -> None:
        _send({"jsonrpc": "2.0", "method": method, "params": params})

    while True:
        msg = _read_message()
        if msg is None:
            break
        method = msg.get("method", "")
        mid = msg.get("id")

        if method == "initialize":
            _send({
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "capabilities": {
                        "textDocumentSync": {"openClose": True, "save": True},
                        "codeActionProvider": True,
                    },
                    "serverInfo": {"name": "tf-analyze", "version": "0.1.0"},
                }
            })

        elif method == "initialized":
            pass

        elif method in ("textDocument/didOpen", "textDocument/didSave"):
            uri = msg["params"]["textDocument"]["uri"]
            findings = _scan_uri(uri)
            _diagnostics[uri] = findings
            _notify("textDocument/publishDiagnostics", {
                "uri": uri,
                "diagnostics": _findings_to_diagnostics(findings),
            })

        elif method == "textDocument/didClose":
            uri = msg["params"]["textDocument"]["uri"]
            _diagnostics.pop(uri, None)
            _notify("textDocument/publishDiagnostics", {"uri": uri, "diagnostics": []})

        elif method == "textDocument/codeAction":
            uri = msg["params"]["textDocument"]["uri"]
            req_line = msg["params"]["range"]["start"]["line"] + 1
            findings = _diagnostics.get(uri, [])
            actions = []
            for f in findings:
                if abs(f["line"] - req_line) > 2:
                    continue
                entry = id_map.get(f["id"], {})
                fix_hcl = entry.get("fix_hcl")
                if not fix_hcl:
                    continue
                actions.append({
                    "title": f"tf-analyze fix: {f['id']}",
                    "kind": "quickfix",
                    "edit": {
                        "changes": {
                            uri: [{
                                "range": {
                                    "start": {"line": f["line"] - 1, "character": 0},
                                    "end":   {"line": f["line"] - 1, "character": 0},
                                },
                                "newText": f"\n# tf-analyze fix for {f['id']}:\n{fix_hcl}\n",
                            }]
                        }
                    }
                })
            _send({"jsonrpc": "2.0", "id": mid, "result": actions})

        elif method == "shutdown":
            _send({"jsonrpc": "2.0", "id": mid, "result": None})

        elif method == "exit":
            sys.exit(0)

        elif mid is not None:
            _send({"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32601, "message": f"Method not found: {method}"}})


def main():
    ap = argparse.ArgumentParser()
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
        default=str(Path(__file__).parent.parent / "catalog"),
        help="Catalog directory",
    )
    ap.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html", "compliance"],
        default="text",
    )
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
        choices=["cis", "pci_dss", "soc2", "all"],
        metavar="FRAMEWORK",
        help=(
            "Compliance framework to map against. Choices: cis (default), "
            "pci_dss, soc2, all. 'all' combines CIS, PCI-DSS v4.0, and "
            "SOC2 Trust Services Criteria in one report. Requires --compliance "
            "or --format compliance."
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
        "--mode",
        choices=["static", "diff", "verify-fixed", "fleet", "trend", "pr-review"],
        default="static",
        help="Execution mode. fleet: multi-repo scan. trend: risk trajectory over git history.",
    )
    ap.add_argument(
        "--lookback",
        type=int,
        default=30,
        metavar="N",
        help="Days of git history to analyse in --mode trend (default: 30).",
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
    ap.add_argument(
        "--only-fixture",
        default=None,
        help="Restrict catalogue to entries listing this fixture name",
    )
    ap.add_argument(
        "--include-stubs",
        action="store_true",
        help="Include catalogue entries with status: stub",
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
        "--diff-base",
        default=None,
        help="Git ref to diff against (e.g., main). Only scan changed .tf files.",
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
    ap.add_argument(
        "--fail-on",
        default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Exit with code 1 if any finding at this urgency or above exists",
    )
    ap.add_argument(
        "--compare",
        default=None,
        help="Path to a prior JSON report to compare against (outputs delta)",
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
        "--use-hcl2",
        action="store_true",
        default=os.environ.get("TF_ANALYZE_USE_HCL2") == "1",
        help=(
            "Enable optional python-hcl2 fast-path for heredoc-aware "
            "attribute extraction. Requires `pip install python-hcl2` — "
            "if the dependency is missing this flag is a no-op and the "
            "regex path is used. Off by default to honor the stdlib-only "
            "promise; can also be enabled via TF_ANALYZE_USE_HCL2=1."
        ),
    )
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
        "--config",
        default=None,
        metavar="PATH",
        help=(
            "Path to .tf-analyze.yaml project config file. "
            "Default: auto-discover in target directory."
        ),
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
    ap.add_argument(
        "--lsp",
        action="store_true",
        default=False,
        help=(
            "Run as a JSON-RPC 2.0 LSP server on stdin/stdout. "
            "Provides real-time diagnostics and code actions for .tf files."
        ),
    )
    args = ap.parse_args()
    if args.use_hcl2:
        _enable_hcl2_or_warn()

    # Route report output: stdout (default) or a file (--output PATH).
    # We shadow `print` for report output only — stderr progress lines
    # always go to sys.stderr and are unaffected.
    _out_file = None
    if args.output:
        _out_file = open(args.output, "w", encoding="utf-8")

    def _emit(text: str) -> None:
        """Write report output to stdout or --output file."""
        if _out_file is not None:
            _out_file.write(text + "\n")
        else:
            print(text)

    catalog_dir = Path(args.catalog).resolve()

    # Normalise targets list (args.targets is None or a list due to action="append")
    if args.targets is None:
        args.targets = []

    # --init: create project config scaffold and exit
    if args.init:
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
        sys.exit(0)

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
        _cmd_list_rules(catalog_dir, args.focus, args.include_stubs)
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
        fleet_targets = _resolve_fleet_targets(args)
        if not fleet_targets:
            print("ERROR: --mode fleet requires at least one --target or --targets-file", file=sys.stderr)
            sys.exit(2)
        fleet_result = _fleet_scan(fleet_targets, entries)
        total = sum(fleet_result["summary"].values())
        print(f"# fleet: {len(fleet_targets)} repos, {total} total findings, {len(fleet_result['fleet_wide'])} fleet-wide", file=sys.stderr)
        _emit(_render_fleet_report(fleet_result, args.format))
        if _out_file is not None:
            _out_file.close()
        sys.exit(0)

    # Trend mode — walk git history and compute per-commit finding deltas
    if args.mode == "trend":
        trend_target = Path(args.targets[0]).resolve() if args.targets else None
        if not trend_target:
            print("ERROR: --mode trend requires --target <git-repo-dir>", file=sys.stderr)
            sys.exit(2)
        lookback = getattr(args, "lookback", 30)
        print(f"# trend: analysing {lookback} days of git history in {trend_target}", file=sys.stderr)
        rows = run_trend(trend_target, entries, lookback)
        print(f"# trend: {len(rows)} commits analysed", file=sys.stderr)
        _emit(_render_trend_table(rows, args.format))
        if _out_file is not None:
            _out_file.close()
        sys.exit(0)

    target = Path(args.targets[0]).resolve()

    # Reports directory — used for auto-compare and verify-fixed discovery
    reports_dir = (
        Path(args.reports_dir)
        if args.reports_dir
        else Path(__file__).parent.parent / "reports"
    )

    # verify-fixed mode — early exit with dedicated output
    if args.mode == "verify-fixed":
        prior = Path(args.prior_report) if args.prior_report else find_latest_prior(reports_dir, ".md")
        if not prior or not prior.exists():
            print(
                f"ERROR: no prior report found (looked in {reports_dir}, "
                f"or --prior-report <path>)",
                file=sys.stderr,
            )
            sys.exit(2)
        # Load corpus for re-probing
        tf_files = [p for p in target.rglob("*.tf") if ".terraform" not in p.parts]
        all_text = {}
        for fp in tf_files:
            try:
                all_text[fp] = _read_normalized(fp)
            except Exception:
                continue
        verify = verify_fixed(prior, target, all_text, entries)
        if args.format == "json":
            _emit(json.dumps(verify, indent=2, default=str))
        else:
            import datetime
            out_path = reports_dir / f"tf-analysis-verify-{datetime.date.today()}.md"
            reports_dir.mkdir(parents=True, exist_ok=True)
            write_verification_report(verify, out_path)
            print(f"# wrote {out_path}")
            for state, rows in verify["results"].items():
                print(f"# {state}: {len(rows)}")
        sys.exit(0)

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

    tf_files = [
        p for p in target.rglob("*.tf") if ".terraform" not in p.parts
    ]
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
        _corpus_hash_val = _corpus_hash(all_text, entries)
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

    # Registry staleness check (opt-in; requires network access)
    if getattr(args, "check_registry", False):
        registry_findings = _check_module_registry_staleness(all_text)
        print(
            f"# registry check: {len(registry_findings)} stale module(s) found",
            file=sys.stderr,
        )
        findings.extend(registry_findings)

    # Auto-fix application — runs before suppression so the patched file
    # re-scan (if the user re-runs) won't report those findings.
    if getattr(args, "apply_fixes", None):
        _handle_apply_fixes(
            args, findings, entries,
            dry_run=(args.apply_fixes == "dry-run"),
        )
        if args.apply_fixes == "apply":
            # Exit after applying so the user can re-run to confirm clean state.
            if getattr(args, "_out_file", None):
                pass  # _out_file closure is local; normal cleanup via finally is N/A
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

    # Build attack graph when requested (consumes all_text + findings)
    attack_graph: dict | None = None
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
    if getattr(args, "compliance", False) or args.format == "compliance":
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

    # PR review mode — post inline comments and exit
    if args.mode == "pr-review":
        _pr_review_mode(args, findings, entries)
        if _out_file is not None:
            _out_file.close()
        return

    if getattr(args, "gen_tests", None):
        written = generate_tftest(findings, entries, Path(args.gen_tests))
        print(f"# gen-tests: wrote {len(written)} file(s) to {args.gen_tests}", file=sys.stderr)

    # Auto-compare: resolve most recent JSON report as the prior when set.
    compare_target = args.compare
    if args.auto_compare and not compare_target:
        prior_json = find_latest_prior(reports_dir, ".json")
        if prior_json:
            compare_target = str(prior_json)
            print(f"# auto-compare against {prior_json}", file=sys.stderr)

    # Report comparison
    if compare_target:
        delta = compare_reports(findings, Path(compare_target))
        print(f"# delta: {len(delta['new'])} new, {len(delta['resolved'])} resolved, "
              f"{len(delta['unchanged'])} unchanged", file=sys.stderr)
        if args.format == "json":
            output = {"findings": findings, "suppressed": suppressed_findings, "delta": delta}
            _emit(json.dumps(output, indent=2))
        elif args.format == "sarif":
            sarif = to_sarif(findings, entries)
            _emit(json.dumps(sarif, indent=2))
        elif args.format == "html":
            _emit(to_html(findings, entries, suppressed_findings, graph=attack_graph, show_fixes=getattr(args, "show_fixes", False), centrality=centrality_scores, compliance_data=compliance_report))
        elif args.format == "compliance":
            if compliance_report:
                _emit(_render_compliance_text(compliance_report))
            else:
                _emit("# No CIS-mapped catalogue entries found.")
        else:
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
            if compliance_report and args.format == "text":
                _emit("\n")
                _emit(_render_compliance_text(compliance_report))
    else:
        # Standard output
        if args.format == "json":
            output_data = {"findings": findings}
            if suppressed_findings:
                output_data["suppressed"] = suppressed_findings
            _emit(json.dumps(output_data, indent=2))
        elif args.format == "sarif":
            sarif = to_sarif(findings, entries)
            _emit(json.dumps(sarif, indent=2))
        elif args.format == "html":
            _emit(to_html(findings, entries, suppressed_findings, graph=attack_graph, show_fixes=getattr(args, "show_fixes", False), centrality=centrality_scores, compliance_data=compliance_report))
        elif args.format == "compliance":
            if compliance_report:
                _emit(_render_compliance_text(compliance_report))
            else:
                _emit("# No CIS-mapped catalogue entries found.")
        else:
            entry_map_out = {e["id"]: e for e in entries}
            for f in findings:
                _emit(f"{f['id']} {f['file']}:{f['line']} {f['resource']}")
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
            if compliance_report and args.format == "text":
                _emit("\n")
                _emit(_render_compliance_text(compliance_report))

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


if __name__ == "__main__":
    main()
