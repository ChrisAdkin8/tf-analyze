"""Infrastructure-tier detector handlers extracted from detect.py (R30.15).

Houses the 9 corpus handlers concerned with workspace-level config:
backends, remote-state references, provider aliases, .tfstate files
in the repo, terraform/provider version constraints, and the
cross-resource graph dispatcher.

All handlers in this module are corpus handlers — they look at the
whole workspace rather than a single file.

Corpus handlers (9):
    backend_inconsistency, backend_missing_arg, remote_state_present,
    provider_alias_unused, provider_alias_module_mismatch,
    tfstate_in_repo, submodule_version_missing,
    providers_version_missing, graph_check
"""
from __future__ import annotations

import re
from pathlib import Path

from _hcl import find_blocks, block_arg_value, brace_walk, strip_hcl_context
from _cross_resource import _GRAPH_CHECKS
from detect import (
    CorpusCtx,
    _register_corpus,
    DATA_START,
    MODULE_START,
    PROVIDER_START,
)


@_register_corpus("backend_inconsistency")
def _corpus_backend_inconsistency(c: CorpusCtx) -> list[dict]:
    """``backend_inconsistency`` — fire when the workspace declares two
    or more ``backend "X" {}`` blocks of different types. Flags all
    but the first.
    """
    backend_re = re.compile(r'^\s*backend\s+"([\w-]+)"\s*\{', re.MULTILINE)
    backends: list[tuple[str, str, int]] = []
    for fp, text in c.all_files_text.items():
        for m in backend_re.finditer(text):
            btype = m.group(1)
            line = text.count("\n", 0, m.start()) + 1
            backends.append((btype, str(fp), line))
    out: list[dict] = []
    if len(backends) >= 2:
        types = set(b[0] for b in backends)
        if len(types) > 1:
            for btype, bfile, bline in backends[1:]:
                out.append({
                    "id": c.eid,
                    "file": bfile,
                    "line": bline,
                    "resource": f"backend.{btype}",
                })
    return out


@_register_corpus("backend_missing_arg")
def _corpus_backend_missing_arg(c: CorpusCtx) -> list[dict]:
    """``backend_missing_arg`` — fire when a backend block of the
    specified type exists but lacks a required argument (e.g. S3
    backend without state locking via ``dynamodb_table``).
    """
    pat = c.pat
    backend_type = pat.get("backend_type")
    arg = pat.get("arg")
    if not backend_type or not arg:
        return []
    backend_re = re.compile(
        r'^\s*backend\s+"' + re.escape(backend_type) + r'"\s*\{',
        re.MULTILINE,
    )
    arg_re = re.compile(r'\b' + re.escape(arg) + r'\s*=')
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for m in backend_re.finditer(text):
            end_after = brace_walk(text, m.end() - 1)
            if end_after is None:
                continue
            end = end_after - 1
            body = text[m.end():end]
            if not arg_re.search(body):
                line = text.count("\n", 0, m.start()) + 1
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": line,
                    "resource": f"backend.{backend_type}",
                })
    return out


@_register_corpus("remote_state_present")
def _corpus_remote_state_present(c: CorpusCtx) -> list[dict]:
    """``remote_state_present`` — fire on every
    ``data "terraform_remote_state" "x"`` block.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, DATA_START):
            dtype, dname = blk["groups"]
            if dtype == "terraform_remote_state":
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"data.terraform_remote_state.{dname}",
                })
    return out


@_register_corpus("provider_alias_unused")
def _corpus_provider_alias_unused(c: CorpusCtx) -> list[dict]:
    """``provider_alias_unused`` — fire on every provider alias declared
    via ``alias = "..."`` that no resource / module references.
    """
    alias_decls: list[tuple[str, str, str, int]] = []
    for fp, text in c.all_files_text.items():
        for blk in find_blocks(text, PROVIDER_START):
            pname = blk["groups"][0]
            alias = block_arg_value(blk["body"], "alias")
            if alias:
                alias_decls.append((pname, alias, str(fp), blk["start_line"]))
    ref_re = re.compile(r'\b([\w-]+)\.([\w-]+)\b')
    refs: set[tuple[str, str]] = set()
    for text in c.all_files_text.values():
        stripped = strip_hcl_context(text)
        for m in ref_re.finditer(stripped):
            refs.add((m.group(1), m.group(2)))
    out: list[dict] = []
    for pname, alias, fp, line in alias_decls:
        if (pname, alias) not in refs:
            out.append({
                "id": c.eid,
                "file": fp,
                "line": line,
                "resource": f"provider.{pname}.{alias}",
            })
    return out


@_register_corpus("provider_alias_module_mismatch")
def _corpus_provider_alias_module_mismatch(c: CorpusCtx) -> list[dict]:
    """``provider_alias_module_mismatch`` — fire when a
    ``module { providers = { ... = name.alias } }`` references a
    provider alias the workspace doesn't declare.
    """
    declared: set[tuple[str, str]] = set()
    for text in c.all_files_text.values():
        for blk in find_blocks(text, PROVIDER_START):
            pname = blk["groups"][0]
            alias = block_arg_value(blk["body"], "alias")
            if alias:
                declared.add((pname, alias))
    providers_block_re = re.compile(r'(?m)^\s*providers\s*=\s*\{([^}]*)\}', re.DOTALL)
    entry_re = re.compile(r'=\s*([\w-]+)\.([\w-]+)')
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for mblk in find_blocks(text, MODULE_START):
            pm = providers_block_re.search(mblk["body"])
            if not pm:
                continue
            for em in entry_re.finditer(pm.group(1)):
                pname, alias = em.group(1), em.group(2)
                if (pname, alias) not in declared:
                    out.append({
                        "id": c.eid,
                        "file": str(fp),
                        "line": mblk["start_line"],
                        "resource": f"module.{mblk['groups'][0]}:{pname}.{alias}",
                    })
    return out


@_register_corpus("tfstate_in_repo")
def _corpus_tfstate_in_repo(c: CorpusCtx) -> list[dict]:
    """``tfstate_in_repo`` — walk the workspace once for ``*.tfstate*``
    files. Such files in a repo are usually accidents (state should
    live in a backend, never a git repo).
    """
    out: list[dict] = []
    seen_dirs: set[str] = set()
    for fp in c.all_files_text:
        d = Path(fp).parent
        if str(d) in seen_dirs:
            continue
        seen_dirs.add(str(d))
        for p in d.rglob("*.tfstate*"):
            if ".terraform" in p.parts:
                continue
            out.append({
                "id": c.eid,
                "file": str(p),
                "line": 1,
                "resource": p.name,
            })
        break  # walk from the outermost target once
    return out


@_register_corpus("submodule_version_missing")
def _corpus_submodule_version_missing(c: CorpusCtx) -> list[dict]:
    """``submodule_version_missing`` — a directory containing .tf files
    but lacking ``required_version`` anywhere — common in submodules
    that inherit the root's constraint only implicitly.
    """
    dirs_with_tf: dict[str, list[str]] = {}
    for fp, text in c.all_files_text.items():
        dirs_with_tf.setdefault(str(Path(fp).parent), []).append(fp)
    out: list[dict] = []
    for d, files in dirs_with_tf.items():
        has_req = any(
            re.search(r'required_version\s*=', c.all_files_text[f])
            for f in files
        )
        if not has_req:
            out.append({
                "id": c.eid,
                "file": str(files[0]),
                "line": 1,
                "resource": f"<module:{Path(d).name}>",
            })
    return out


@_register_corpus("providers_version_missing")
def _corpus_providers_version_missing(c: CorpusCtx) -> list[dict]:
    """``providers_version_missing`` — find ``terraform { required_providers
    { ... } }`` blocks and flag any provider entry that lacks a version
    constraint.
    """
    tf_block_re = re.compile(r"(?m)^\s*terraform\s*\{")
    rp_block_re = re.compile(r"required_providers\s*\{")
    entry_re = re.compile(r"(\w[\w-]*)\s*=\s*\{([^{}]+)\}", re.DOTALL)
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        for tf_m in tf_block_re.finditer(text):
            tf_end_after = brace_walk(text, tf_m.end() - 1)
            if tf_end_after is None:
                continue
            tf_end = tf_end_after - 1
            tf_body = text[tf_m.end():tf_end]
            rp = rp_block_re.search(tf_body)
            if not rp:
                continue
            rp_start = tf_m.end() + rp.end()
            rp_end_after = brace_walk(text, rp_start - 1)
            if rp_end_after is None:
                continue
            rp_end = rp_end_after - 1
            rp_body = text[rp_start:rp_end]
            for em in entry_re.finditer(rp_body):
                provider_name = em.group(1)
                entry_body = em.group(2)
                if not re.search(r"\bversion\s*=", entry_body):
                    entry_pos = rp_start + em.start()
                    line_no = text.count("\n", 0, entry_pos) + 1
                    out.append({
                        "id": c.eid,
                        "file": str(fp),
                        "line": line_no,
                        "resource": f"<provider:{provider_name}>",
                    })
    return out


@_register_corpus("graph_check")
def _corpus_graph_check(c: CorpusCtx) -> list[dict]:
    """``graph_check`` — cross-resource detector. The pattern names a
    registered graph function (from ``_cross_resource._GRAPH_CHECKS``);
    we dispatch to it with a uniform index of all resources keyed by
    ``<type>.<name>`` → block dict.
    """
    fn_name = c.pat.get("function")
    fn = _GRAPH_CHECKS.get(fn_name)
    if not fn:
        return []
    out: list[dict] = []
    for finding in fn(c.resource_index_cache, c.all_files_text):
        finding["id"] = c.eid
        out.append(finding)
    return out
