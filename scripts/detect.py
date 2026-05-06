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
import io
import json
import os
import re
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
    """Check if a block body has a top-level argument named `arg`."""
    pat = re.compile(rf'(?m)^\s*{re.escape(arg)}\s*=', re.MULTILINE)
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


# ---- Detection ----------------------------------------------------------

def detect_in_file(file_path: Path, text: str, entries: list[dict]) -> list[dict]:
    findings = []
    resources = find_blocks(text, RESOURCE_START)
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
                    glob.lstrip("*")
                ):
                    continue
                search_text = strip_hcl_context(text) if pat.get("hcl_context") else text
                for m in regex.finditer(search_text):
                    line = search_text.count("\n", 0, m.start()) + 1
                    findings.append({"id": eid, "file": str(file_path), "line": line, "resource": ""})
            elif kind == "resource_arg":
                if not all(k in pat for k in ("resource", "arg", "regex")):
                    continue
                rt = pat["resource"]
                arg = pat["arg"]
                regex = re.compile(pat["regex"])
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != rt:
                        continue
                    val = block_arg_value(blk["body"], arg)
                    if val is not None and regex.search(val):
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
                arg_path = pat.get("arg") or pat.get("nested_path") or ""
                if not arg_path:
                    continue
                for blk in resources:
                    btype, bname = blk["groups"]
                    if btype != rt:
                        continue
                    if "." in arg_path:
                        present = block_has_nested_path(blk["body"], arg_path)
                    else:
                        present = block_has_arg(blk["body"], arg_path)
                    if not present:
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


_GRAPH_CHECKS = {
    "logging_target_public": _graph_logging_target_public,
    "gke_nodepool_secure_boot": _graph_gke_nodepool_secure_boot,
    "kms_location_parity": _graph_kms_location_parity,
    "iam_member_breadth": _graph_iam_member_breadth,
}


# ---- SARIF output --------------------------------------------------------

SARIF_HELP_URI_BASE = (
    "https://github.com/anthropics/claude-code/blob/main/"
    "skills/tf-analyze/catalog/{id}.yaml"
)


def _sarif_fingerprint(finding: dict) -> str:
    """Stable partial fingerprint so GitHub Code Scanning can deduplicate."""
    key = f"{finding['id']}|{finding.get('file','')}|{finding.get('resource','')}"
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()[:16]


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
            "partialFingerprints": {
                "tfAnalyze/v1": _sarif_fingerprint(f),
            },
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
                        "informationUri": "https://github.com/anthropics/claude-code",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


# ---- HTML output ---------------------------------------------------------

def to_html(findings: list[dict], entries: list[dict], suppressed: list[dict]) -> str:
    """Produce a single-file HTML report, scalable to hundreds of findings.

    Groups by catalogue ID, collapsible per group, sortable table header.
    No external CSS/JS — self-contained for offline review.
    """
    entry_map = {e["id"]: e for e in entries}
    by_id: dict[str, list[dict]] = {}
    for f in findings:
        by_id.setdefault(f["id"], []).append(f)
    # Sort groups by urgency then count
    urgency_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_ids = sorted(
        by_id.keys(),
        key=lambda i: (
            urgency_rank.get(entry_map.get(i, {}).get("default_urgency", "MEDIUM"), 2),
            -len(by_id[i]),
            i,
        ),
    )
    rows = []
    for eid in sorted_ids:
        entry = entry_map.get(eid, {})
        urgency = entry.get("default_urgency", "MEDIUM")
        title = entry.get("title", eid)
        fs = by_id[eid]
        detail_rows = "".join(
            f"<tr><td><code>{f.get('file','')}</code>:{f.get('line','')}</td>"
            f"<td><code>{f.get('resource','')}</code></td></tr>"
            for f in fs
        )
        rows.append(
            f"<details><summary><span class='u u-{urgency.lower()}'>{urgency}</span> "
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
    return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>tf-analyze report</title>
<style>
body{{font:14px/1.5 -apple-system,system-ui,sans-serif;max-width:960px;margin:2em auto;padding:0 1em;color:#222}}
code{{font:12px/1.3 ui-monospace,monospace;background:#f4f4f4;padding:1px 4px;border-radius:3px}}
details{{border:1px solid #e0e0e0;border-radius:6px;margin:.4em 0;padding:.6em 1em;background:#fafafa}}
summary{{cursor:pointer;user-select:none}}
.u{{padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600;color:#fff}}
.u-critical{{background:#7a0b0b}} .u-high{{background:#b02a2a}} .u-medium{{background:#c27a00}} .u-low{{background:#5a7b33}} .u-info{{background:#4a6a8a}}
table.locs{{border-collapse:collapse;margin-top:.5em;width:100%;font-size:13px}}
table.locs th,table.locs td{{text-align:left;padding:.3em .5em;border-bottom:1px solid #eee}}
h1{{margin:0 0 .2em}} .meta{{color:#666;margin-bottom:1.5em}}
</style></head><body>
<h1>tf-analyze report</h1>
<div class='meta'>{len(findings)} findings across {len(by_id)} rules.</div>
{''.join(rows)}
{suppressed_section}
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
    fid = data.get("id")
    fname = Path(source).stem
    if fid and fid != fname:
        errs.append(
            f"{source}: id '{fid}' does not match filename stem '{fname}'"
        )
    return errs


def load_catalog(
    catalog_dir: Path,
    include_stubs: bool = False,
    strict: bool = False,
) -> list[dict]:
    """Load catalogue YAMLs with schema validation.

    Stubs (status: stub) are excluded by default — their patterns may be
    incomplete and would produce false positives in normal scans. Pass
    include_stubs=True only when validating that the stub itself parses.

    Validation errors print to stderr as 'ERROR:' lines and the offending
    entry is skipped. With strict=True, a single error aborts the load
    via sys.exit(2). Default is non-strict so a stale catalogue entry
    doesn't break every CI run.
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
                if not (rt and arg and regex_str):
                    continue
                regex = re.compile(regex_str)
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    val = (r.get("values") or {}).get(arg)
                    if val is None:
                        continue
                    if regex.search(str(val)):
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
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    val = _plan_value_at_path(r.get("values") or {}, arg_path)
                    if val in (None, [], {}):
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


# ---- Main ---------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    # --target is required for scan modes but not for the meta-commands
    # (--list-rules / --explain / --new-rule). Validation happens after
    # parse so users can `--list-rules` without supplying a target.
    ap.add_argument("--target", help="Directory to scan (required for scans)")
    ap.add_argument(
        "--catalog",
        default=str(Path(__file__).parent.parent / "catalog"),
        help="Catalog directory",
    )
    ap.add_argument(
        "--format",
        choices=["text", "json", "sarif", "html"],
        default="text",
    )
    ap.add_argument(
        "--mode",
        choices=["static", "diff", "verify-fixed"],
        default="static",
        help="Execution mode. verify-fixed parses a prior report and re-probes.",
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
    args = ap.parse_args()
    if args.use_hcl2:
        _enable_hcl2_or_warn()

    catalog_dir = Path(args.catalog).resolve()

    # Meta-commands run on the catalogue alone — no target needed.
    if args.list_rules:
        _cmd_list_rules(catalog_dir, args.focus, args.include_stubs)
        sys.exit(0)
    if args.explain:
        sys.exit(_cmd_explain(catalog_dir, args.explain))
    if args.new_rule:
        sys.exit(_cmd_new_rule(args.new_rule))

    if not args.target:
        print(
            "ERROR: --target is required for scan modes. "
            "Use --list-rules / --explain / --new-rule for catalogue ops.",
            file=sys.stderr,
        )
        sys.exit(2)
    target = Path(args.target).resolve()

    entries = load_catalog(
        catalog_dir,
        include_stubs=args.include_stubs,
        strict=args.strict_catalog,
    )
    if not entries:
        print(f"ERROR: no catalogue entries loaded from {catalog_dir}", file=sys.stderr)
        sys.exit(2)

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
            print(json.dumps(verify, indent=2, default=str))
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
    findings: list[dict] = []
    for fp, text in all_text.items():
        if diff_files is not None and fp not in diff_files:
            continue
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

    # Corpus-level checks run against all files (even in diff mode)
    corpus_findings = detect_corpus(target, all_text, entries)
    if diff_files is not None:
        # Filter corpus findings to only those touching changed files
        corpus_findings = [
            f for f in corpus_findings
            if Path(f["file"]).resolve() in diff_files or f["line"] == 0
        ]
    findings.extend(corpus_findings)

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
            print(json.dumps(output, indent=2))
        elif args.format == "sarif":
            sarif = to_sarif(findings, entries)
            print(json.dumps(sarif, indent=2))
        elif args.format == "html":
            print(to_html(findings, entries, suppressed_findings))
        else:
            if delta["new"]:
                print("# NEW findings:")
                for f in delta["new"]:
                    print(f"  + {f['id']} {f['file']}:{f['line']} {f['resource']}")
            if delta["resolved"]:
                print("# RESOLVED findings:")
                for f in delta["resolved"]:
                    print(f"  - {f['id']} {f['file']}:{f['line']} {f['resource']}")
            if delta["unchanged"]:
                print(f"# {len(delta['unchanged'])} unchanged finding(s)")
    else:
        # Standard output
        if args.format == "json":
            output_data = {"findings": findings}
            if suppressed_findings:
                output_data["suppressed"] = suppressed_findings
            print(json.dumps(output_data, indent=2))
        elif args.format == "sarif":
            sarif = to_sarif(findings, entries)
            print(json.dumps(sarif, indent=2))
        elif args.format == "html":
            print(to_html(findings, entries, suppressed_findings))
        else:
            for f in findings:
                print(f"{f['id']} {f['file']}:{f['line']} {f['resource']}")
            if suppressed_findings:
                print(f"# ({len(suppressed_findings)} suppressed)", file=sys.stderr)
            if not findings:
                print("# no findings", file=sys.stderr)

    # Exit code for CI gating
    if args.fail_on:
        urgency_rank = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        threshold = urgency_rank.get(args.fail_on, 3)
        entry_map = {e["id"]: e for e in entries}
        for f in findings:
            entry = entry_map.get(f["id"])
            if entry:
                finding_rank = urgency_rank.get(entry.get("default_urgency", "MEDIUM"), 3)
                if finding_rank <= threshold:
                    sys.exit(1)


if __name__ == "__main__":
    main()
