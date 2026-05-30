"""Security-tier detector handlers extracted from detect.py (R30.15).

Houses the 9 handlers that look for credential leaks, IAM-policy
mis-configurations, world-open firewalls and command injection via
data sources. Each handler is registered with the central dispatch
table by virtue of the ``@_register_infile`` / ``@_register_corpus``
decorator on its definition; importing this module is what triggers
the registration. See the matching block in ``detect.py``.

In-file handlers (6):
    variable_credential_pattern, iam_policy_analysis, helm_set_value,
    iam_json_policy_analysis, firewall_open_port, high_entropy_string

Corpus handlers (4):
    output_sensitive_leak, cross_module, templatefile_sensitive_leak,
    data_external_injection
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from _hcl import (
    find_blocks,
    block_arg_value,
    brace_walk,
    strip_hcl_context,
    _hcl_object_to_json,
)
from detect import (
    InFileCtx,
    CorpusCtx,
    _register_infile,
    _register_corpus,
    DATA_START,
    MODULE_START,
    VARIABLE_START,
    OUTPUT_START,
    RESOURCE_START,
    SENSITIVE_TRUE_RE,
    VAR_REF_RE,
)


# ---- In-file handlers ---------------------------------------------------

@_register_infile("variable_credential_pattern")
def _detect_variable_credential_pattern(c: InFileCtx) -> list[dict]:
    """``variable_credential_pattern`` — variables whose name suggests
    they hold a credential (``*_password``, ``*_token``, ``*_secret``,
    ``*_key``, …) MUST have ``sensitive = true`` — without it,
    ``terraform plan`` / ``terraform output`` print the value into CI
    logs. The catalogue can override the name regex via ``name_regex``.
    """
    raw_re = c.pat.get("name_regex") or (
        r"^.*_(password|passwd|pwd|token|secret|secrets|"
        r"apikey|api_key|access_key|private_key|credential|"
        r"credentials|auth|oauth)$"
    )
    try:
        name_re = re.compile(raw_re, re.IGNORECASE)
    except re.error:
        return []
    out: list[dict] = []
    for blk in c.variables:
        var_name = blk["groups"][0]
        if not name_re.match(var_name):
            continue
        if re.search(r"(?m)^\s*sensitive\s*=\s*true\s*$", blk["body"]):
            continue
        out.append({
            "id": c.eid,
            "file": str(c.file_path),
            "line": blk["start_line"],
            "resource": f"var.{var_name}",
        })
    return out


@_register_infile("iam_policy_analysis")
def _detect_iam_policy_analysis(c: InFileCtx) -> list[dict]:
    """``iam_policy_analysis`` — walk every ``data
    "aws_iam_policy_document"`` block and each nested ``statement {}``.
    The pattern's ``check`` field selects what to look for inside an
    Allow statement:

    * ``wildcard_action`` — actions list contains ``"*"``
    * ``wildcard_resource`` — resources list contains ``"*"``
    * ``public_principal`` — principals ``identifiers = ["*"]``
    * ``wildcard_action_iam`` — any ``iam:*`` action (privesc class)
    * ``wildcard_action_and_resource`` — both action and resource ``"*"``
    * ``not_action_or_not_resource`` — uses NotAction/NotResource

    Uses the shared ``brace_walk`` for both the outer statement and
    inner principals blocks (quote-aware — an action ARN containing
    ``bucket-{*}-policy`` no longer corrupts the depth count).
    """
    check = c.pat.get("check")
    if not check:
        return []
    out: list[dict] = []
    for dblk in find_blocks(c.text, DATA_START):
        dtype, dname = dblk["groups"]
        if dtype != "aws_iam_policy_document":
            continue
        body = dblk["body"]
        for sm in re.finditer(r'(?m)^\s*statement\s*\{', body):
            s_end_after = brace_walk(body, sm.end() - 1)
            if s_end_after is None:
                continue
            s_end = s_end_after - 1
            sbody = body[sm.end():s_end]
            eff = block_arg_value(sbody, "effect")
            if eff and eff.strip().strip('"').lower() == "deny":
                continue
            actions = block_arg_value(sbody, "actions") or ""
            resources_l = block_arg_value(sbody, "resources") or ""
            not_actions = block_arg_value(sbody, "not_actions") or ""
            not_resources = block_arg_value(sbody, "not_resources") or ""
            has_wild_action = '"*"' in actions
            has_wild_resource = '"*"' in resources_l
            has_iam_wild = bool(re.search(r'"iam:[^"]*\*"', actions))
            has_public_principal = False
            for pm in re.finditer(r'(?m)^\s*principals\s*\{', sbody):
                p_end_after = brace_walk(sbody, pm.end() - 1)
                if p_end_after is None:
                    continue
                p_end = p_end_after - 1
                pbody = sbody[pm.end():p_end]
                ids = block_arg_value(pbody, "identifiers") or ""
                if '"*"' in ids:
                    has_public_principal = True
                    break
            triggered = False
            if check == "wildcard_action" and has_wild_action:
                triggered = True
            elif check == "wildcard_resource" and has_wild_resource:
                triggered = True
            elif check == "public_principal" and has_public_principal:
                triggered = True
            elif check == "wildcard_action_iam" and has_iam_wild:
                triggered = True
            elif (check == "wildcard_action_and_resource"
                  and has_wild_action and has_wild_resource):
                triggered = True
            elif check == "not_action_or_not_resource" and (
                not_actions or not_resources
            ):
                triggered = True
            if triggered:
                stmt_line = dblk["start_line"] + body[: sm.start()].count("\n")
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": stmt_line,
                    "resource": f"data.aws_iam_policy_document.{dname}",
                })
    return out


@_register_infile("helm_set_value")
def _detect_helm_set_value(c: InFileCtx) -> list[dict]:
    """``helm_set_value`` — walk ``resource "helm_release" "x" { set
    { name=...; value=... } }`` and fire when a specific (name, regex)
    pair matches. Catalogue pattern fields: ``name`` (exact match,
    e.g. ``service.type``) and ``regex`` (against the value).
    """
    target_name = c.pat.get("name")
    value_regex = c.pat.get("regex")
    if not target_name or not value_regex:
        return []
    vrx = re.compile(value_regex)
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != "helm_release":
            continue
        body = blk["body"]
        for sm in re.finditer(r'(?m)^\s*set\s*\{', body):
            end_after = brace_walk(body, sm.end() - 1)
            if end_after is None:
                continue
            end = end_after - 1
            sbody = body[sm.end():end]
            n = block_arg_value(sbody, "name") or ""
            v = block_arg_value(sbody, "value") or ""
            if n.strip() == target_name and vrx.search(str(v)):
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": blk["start_line"],
                    "resource": f"helm_release.{bname}",
                })
                break
    return out


@_register_infile("iam_json_policy_analysis")
def _detect_iam_json_policy_analysis(c: InFileCtx) -> list[dict]:
    """``iam_json_policy_analysis`` — inline JSON-policy analysis on
    resources like ``aws_iam_policy`` / ``aws_iam_role_policy`` whose
    ``policy`` argument is ``jsonencode({...})``. The same ``check``
    vocabulary as ``iam_policy_analysis`` (wildcard_action, etc.).

    The ``jsonencode(...)`` call body is extracted via ``brace_walk``
    with paren delimiters, then run through ``_hcl_object_to_json``
    for structural inspection.
    """
    check = c.pat.get("check")
    resource_types = c.pat.get("resources") or [
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    ]
    if not check:
        return []
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype not in resource_types:
            continue
        body = blk["body"]
        pm = re.search(r'(?m)^\s*policy\s*=\s*jsonencode\(', body)
        if not pm:
            continue
        end_after = brace_walk(body, pm.end() - 1, opens="(", closes=")")
        if end_after is None:
            continue
        end = end_after - 1
        raw = body[pm.end():end].strip()
        parsed = _hcl_object_to_json(raw)
        if parsed is None:
            continue
        statements = parsed.get("Statement") or []
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            eff = str(stmt.get("Effect", "Allow")).lower()
            if eff == "deny":
                continue
            actions = stmt.get("Action") or []
            resources_l = stmt.get("Resource") or []
            not_actions = stmt.get("NotAction") or []
            not_resources = stmt.get("NotResource") or []
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources_l, str):
                resources_l = [resources_l]
            principal = stmt.get("Principal") or {}
            has_public_principal = False
            if principal == "*":
                has_public_principal = True
            elif isinstance(principal, dict):
                for v in principal.values():
                    if v == "*" or (isinstance(v, list) and "*" in v):
                        has_public_principal = True
                        break
            has_wild_action = "*" in actions
            has_wild_resource = "*" in resources_l
            has_iam_wild = any(
                isinstance(a, str) and a.startswith("iam:") and "*" in a
                for a in actions
            )
            triggered = False
            if check == "wildcard_action" and has_wild_action:
                triggered = True
            elif check == "wildcard_resource" and has_wild_resource:
                triggered = True
            elif check == "public_principal" and has_public_principal:
                triggered = True
            elif check == "wildcard_action_iam" and has_iam_wild:
                triggered = True
            elif (check == "wildcard_action_and_resource"
                  and has_wild_action and has_wild_resource):
                triggered = True
            elif check == "not_action_or_not_resource" and (
                not_actions or not_resources
            ):
                triggered = True
            if triggered:
                out.append({
                    "id": c.eid,
                    "file": str(c.file_path),
                    "line": blk["start_line"],
                    "resource": f"{btype}.{bname}",
                })
                break  # one finding per resource is enough
    return out


@_register_infile("firewall_open_port")
def _detect_firewall_open_port(c: InFileCtx) -> list[dict]:
    """``firewall_open_port`` — ``google_compute_firewall`` with
    ``source_ranges`` containing 0.0.0.0/0 AND an ``allow {}`` block
    whose ``ports`` list contains the configured port. Detects the
    classic "world-open SSH/RDP/SQL" pattern. Supports port ranges
    like ``"22-22"`` via numeric containment.
    """
    ports = c.pat.get("ports") or []
    if not ports:
        return []
    want_ports = {str(p) for p in ports}
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        if btype != "google_compute_firewall":
            continue
        body = blk["body"]
        if "0.0.0.0/0" not in body:
            continue
        matched = False
        for am in re.finditer(r'(?m)^\s*allow\s*\{', body):
            a_end_after = brace_walk(body, am.end() - 1)
            if a_end_after is None:
                continue
            a_end = a_end_after - 1
            allow_body = body[am.end():a_end]
            port_match = re.search(r'ports\s*=\s*\[([^\]]+)\]', allow_body)
            if not port_match:
                continue
            listed = re.findall(r'"([^"]+)"', port_match.group(1))
            for p in listed:
                if p in want_ports:
                    matched = True
                    break
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
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"{btype}.{bname}",
            })
    return out


# ---- high-entropy secret detection -------------------------------------

# Token charset: base64 (standard + url-safe) and hex. Real hex strings
# (16 symbols → H tops out ≈3.7) sit *below* the default 4.0 threshold, so
# git SHAs / image digests fall out naturally while genuine base64 tokens
# (62+ symbols, H≈4.1–4.6) clear it — entropy itself does the separation.
_ENTROPY_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")

# `name = "value"` single-line literal assignments. Interpolations and
# references are filtered out by inspecting the captured value below.
_ENTROPY_ASSIGN_RE = re.compile(r'(?m)([A-Za-z_][\w-]*)\s*=\s*"([^"\n]*)"')

# Cloud resource-id prefixes: structured, base64-charset, occasionally
# H>4.0 (e.g. `ami-0abcdef1234567890`) but never secrets.
_ENTROPY_ID_PREFIXES = (
    "ami-", "vol-", "vpc-", "subnet-", "sg-", "snap-", "rtb-", "acl-",
    "eni-", "igw-", "nat-", "i-", "eipalloc-", "pl-", "fsg-", "tgw-",
)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of ``s`` in bits/character (0.0 for empty)."""
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_high_entropy_secret(value: str, *, min_len: int, max_len: int,
                            min_entropy: float) -> bool:
    """True when ``value`` looks like a hardcoded high-entropy token.

    Charset-gated (base64/token) + length-bounded + entropy-thresholded,
    excluding interpolations/references and cloud resource-ids. The
    charset+entropy combination lets hex strings (git SHAs, image digests,
    H≈3.7) fall out below a base64 token (H≈4.1+), so v1 needs no separate
    hex handling — and avoids the git-SHA false-positive class.
    """
    if not (min_len <= len(value) <= max_len):
        return False
    if "${" in value or "$(" in value:          # interpolation / shell
        return False
    if not _ENTROPY_TOKEN_RE.match(value):       # not token charset
        return False
    low = value.lower()
    if any(low.startswith(p) for p in _ENTROPY_ID_PREFIXES):
        return False
    # Readable kebab/snake-case names (bucket names, resource names) can clear
    # the entropy bar by length while using a single character class; genuine
    # tokens mix at least two of {lowercase, uppercase, digit}. This filters the
    # common `my-app-prod-logs-bucket-name`-style false positive.
    classes = (any(c.islower() for c in value)
               + any(c.isupper() for c in value)
               + any(c.isdigit() for c in value))
    if classes < 2:
        return False
    return _shannon_entropy(value) >= min_entropy


@_register_infile("high_entropy_string")
def _detect_high_entropy_string(c: InFileCtx) -> list[dict]:
    """``high_entropy_string`` — flag string literals whose Shannon entropy
    marks them as probable hardcoded secrets (API tokens, access keys),
    *regardless of the argument name*. Complements the name/prefix-based
    ``grep`` secret rules, which miss tokens in oddly-named fields.

    Catalogue pattern fields (all optional, with defaults):
      ``min_length`` (20), ``max_length`` (100), ``min_entropy`` (4.0).
    Comments are stripped first (length-preserving, so line numbers stay
    accurate); interpolations/references, cloud resource-ids, and
    hex/git-SHA-class strings are excluded (see _is_high_entropy_secret).
    """
    min_len = int(c.pat.get("min_length", 20))
    max_len = int(c.pat.get("max_length", 100))
    min_entropy = float(c.pat.get("min_entropy", 4.0))
    out: list[dict] = []
    for blk in c.resources:
        btype, bname = blk["groups"]
        body = strip_hcl_context(blk["body"])   # blank comments, keep offsets
        seen: set[tuple[str, str]] = set()
        for m in _ENTROPY_ASSIGN_RE.finditer(body):
            arg, value = m.group(1), m.group(2)
            if (arg, value) in seen:
                continue
            if not _is_high_entropy_secret(
                value, min_len=min_len, max_len=max_len, min_entropy=min_entropy
            ):
                continue
            seen.add((arg, value))
            line = blk["start_line"] + body.count("\n", 0, m.start())
            ent = _shannon_entropy(value)
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": line,
                "resource": f"{btype}.{bname}",
                "context": (
                    f"high-entropy string assigned to `{arg}` "
                    f"(entropy {ent:.2f} bits/char, length {len(value)}) "
                    f"— probable hardcoded secret"
                ),
            })
    return out


# ---- Corpus handlers ----------------------------------------------------

@_register_corpus("output_sensitive_leak")
def _corpus_output_sensitive_leak(c: CorpusCtx) -> list[dict]:
    """``output_sensitive_leak`` — fire on every ``output`` block that
    references a sensitive variable but lacks ``sensitive = true``.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        dirkey = str(Path(fp).parent)
        for blk in find_blocks(text, OUTPUT_START):
            if SENSITIVE_TRUE_RE.search(blk["body"]):
                continue
            for vm in VAR_REF_RE.finditer(blk["body"]):
                vname = vm.group(1)
                if c.sensitive_vars.get((dirkey, vname)):
                    out.append({
                        "id": c.eid,
                        "file": str(fp),
                        "line": blk["start_line"],
                        "resource": f"output.{blk['groups'][0]}",
                    })
                    break
    return out


@_register_corpus("cross_module")
def _corpus_cross_module(c: CorpusCtx) -> list[dict]:
    """``cross_module`` — fire when a sensitive variable flows from
    caller into a child module whose corresponding variable lacks
    ``sensitive = true``. Round-4 audit fix #6: tolerates symlink loops
    / permission errors via try/except (OSError, ValueError).
    """
    out: list[dict] = []
    arg_re = re.compile(r'(?m)^\s*([\w-]+)\s*=\s*var\.([\w-]+)\s*(?:#.*)?$')
    for fp, text in c.all_files_text.items():
        caller_dir = Path(fp).parent
        for mblk in find_blocks(text, MODULE_START):
            src = block_arg_value(mblk["body"], "source")
            if not src or not src.startswith("."):
                continue
            try:
                child_dir = (caller_dir / src).resolve()
                if not child_dir.is_dir():
                    continue
            except (OSError, ValueError):
                continue
            for am in arg_re.finditer(mblk["body"]):
                child_arg = am.group(1)
                caller_var = am.group(2)
                if child_arg == "source":
                    continue
                if not c.sensitive_vars.get((str(caller_dir), caller_var)):
                    continue
                child_marked = False
                child_found = False
                for cfp, ctext in c.all_files_text.items():
                    try:
                        if Path(cfp).parent.resolve() != child_dir:
                            continue
                    except (OSError, ValueError):
                        continue
                    for cblk in find_blocks(ctext, VARIABLE_START):
                        if cblk["groups"][0] != child_arg:
                            continue
                        child_found = True
                        if re.search(r'(?m)^\s*sensitive\s*=\s*true\s*$', cblk["body"]):
                            child_marked = True
                        break
                if child_found and not child_marked:
                    out.append({
                        "id": c.eid,
                        "file": str(fp),
                        "line": mblk["start_line"],
                        "resource": f"module.{mblk['groups'][0]}.{child_arg}",
                    })
    return out


@_register_corpus("templatefile_sensitive_leak")
def _corpus_templatefile_sensitive_leak(c: CorpusCtx) -> list[dict]:
    """``templatefile_sensitive_leak`` — find ``templatefile()`` calls
    that interpolate sensitive variables.
    """
    tf_call_re = re.compile(r'templatefile\s*\([^,]+,\s*\{([^}]*)\}', re.DOTALL)
    var_ref_re = re.compile(r'\bvar\.([\w-]+)')
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        dirkey = str(Path(fp).parent)
        for m in tf_call_re.finditer(text):
            arg_block = m.group(1)
            for vm in var_ref_re.finditer(arg_block):
                vname = vm.group(1)
                if c.sensitive_vars.get((dirkey, vname)):
                    line = text.count("\n", 0, m.start()) + 1
                    out.append({
                        "id": c.eid,
                        "file": str(fp),
                        "line": line,
                        "resource": f"templatefile(var.{vname})",
                    })
    return out


@_register_corpus("data_external_injection")
def _corpus_data_external_injection(c: CorpusCtx) -> list[dict]:
    """``data_external_injection`` — fire on ``data "external"`` blocks
    whose ``program = [ ... var.X ... ]`` interpolates a variable into
    the spawned subprocess argv.
    """
    prog_re = re.compile(r'(?m)^\s*program\s*=\s*\[(.*?)\]', re.DOTALL)
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, DATA_START):
            if blk["groups"][0] != "external":
                continue
            pm = prog_re.search(blk["body"])
            if pm and re.search(r'var\.[\w-]+', pm.group(1)):
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"data.external.{blk['groups'][1]}",
                })
    return out
