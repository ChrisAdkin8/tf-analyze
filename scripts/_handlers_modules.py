"""Module-lifecycle detector handlers extracted from detect.py (R30.15).

Houses the 7 handlers concerned with module hygiene: missing
descriptions, unused declarations, missing test files, orphaned
module directories, and registry-fingerprint module-reuse detection.

In-file handlers (2):
    variable_missing_description, output_missing_description

Corpus handlers (5):
    variable_unused, output_unused, module_missing_tests,
    module_unused, registry_fingerprint
"""
from __future__ import annotations

import re
from pathlib import Path

from _hcl import find_blocks, block_arg_value
from detect import (
    InFileCtx,
    CorpusCtx,
    _register_infile,
    _register_corpus,
    DESC_RE,
    OUTPUT_START,
    VARIABLE_START,
    MODULE_START,
    _check_registry_fingerprint,
)


# ---- In-file handlers ---------------------------------------------------

@_register_infile("variable_missing_description")
def _detect_variable_missing_description(c: InFileCtx) -> list[dict]:
    """``variable_missing_description`` — fire on every ``variable`` block
    that has no ``description = "..."`` attribute.
    """
    out: list[dict] = []
    for blk in c.variables:
        if not DESC_RE.search(blk["body"]):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"var.{blk['groups'][0]}",
            })
    return out


@_register_infile("output_missing_description")
def _detect_output_missing_description(c: InFileCtx) -> list[dict]:
    """``output_missing_description`` — fire on every ``output`` block
    that has no ``description`` attribute.
    """
    out: list[dict] = []
    for blk in find_blocks(c.text, OUTPUT_START):
        if not DESC_RE.search(blk["body"]):
            out.append({
                "id": c.eid,
                "file": str(c.file_path),
                "line": blk["start_line"],
                "resource": f"output.{blk['groups'][0]}",
            })
    return out


# ---- Corpus handlers ----------------------------------------------------

@_register_corpus("variable_unused")
def _corpus_variable_unused(c: CorpusCtx) -> list[dict]:
    """``variable_unused`` — fire on every ``variable`` whose name is
    not referenced via ``var.X`` anywhere in the same directory.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        dirkey = str(Path(fp).parent)
        refs = c.var_refs_by_dir.get(dirkey, set())
        for blk in find_blocks(text, VARIABLE_START):
            vname = blk["groups"][0]
            if vname not in refs:
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"var.{vname}",
                })
    return out


@_register_corpus("output_unused")
def _corpus_output_unused(c: CorpusCtx) -> list[dict]:
    """``output_unused`` — fire on a child-module output that no caller
    consumes via ``module.X.output_name``. Skips root-module outputs.
    """
    out: list[dict] = []
    for fp, text in c.all_files_text.items():
        fp_dir = str(Path(fp).parent)
        consuming_mod_names = [
            mn for mn, sd in c.module_sources.items() if sd == fp_dir
        ]
        if not consuming_mod_names:
            continue
        for blk in find_blocks(text, OUTPUT_START):
            oname = blk["groups"][0]
            consumed = any(
                (mn, oname) in c.output_refs for mn in consuming_mod_names
            )
            if not consumed:
                out.append({
                    "id": c.eid,
                    "file": str(fp),
                    "line": blk["start_line"],
                    "resource": f"output.{oname}",
                })
    return out


@_register_corpus("module_missing_tests")
def _corpus_module_missing_tests(c: CorpusCtx) -> list[dict]:
    """``module_missing_tests`` — fire once per directory that has .tf
    files but no ``.tftest.hcl`` (TF 1.6+ native tests).
    """
    out: list[dict] = []
    checked_dirs: set[str] = set()
    for fp in c.all_files_text:
        dirkey = str(Path(fp).parent)
        if dirkey in checked_dirs:
            continue
        checked_dirs.add(dirkey)
        dir_path = Path(dirkey)
        test_files = list(dir_path.glob("*.tftest.hcl"))
        tests_subdir = dir_path / "tests"
        if tests_subdir.is_dir():
            test_files.extend(tests_subdir.glob("*.tftest.hcl"))
        if not test_files:
            first_tf = None
            for f in c.all_files_text:
                if str(Path(f).parent) == dirkey:
                    first_tf = f
                    break
            out.append({
                "id": c.eid,
                "file": str(first_tf or dirkey),
                "line": 1,
                "resource": f"<module:{dir_path.name}>",
            })
    return out


@_register_corpus("module_unused")
def _corpus_module_unused(c: CorpusCtx) -> list[dict]:
    """``module_unused`` — fire once per local-module directory that no
    caller references via ``module { source = "<relpath>" }``. A
    directory counts as "module-like" only if it declares at least one
    variable or output block. Deliberately conservative (false
    positives here would be loud).
    """
    referenced_dirs: set[str] = set()
    module_like_dirs: dict[str, str] = {}
    _VAR_OR_OUT = re.compile(r'(?m)^\s*(?:variable|output)\s+"[\w-]+"\s*\{')
    for fp, text in c.all_files_text.items():
        caller_dir = Path(fp).parent
        dirkey = str(caller_dir)
        if _VAR_OR_OUT.search(text):
            module_like_dirs.setdefault(dirkey, str(fp))
        for mblk in find_blocks(text, MODULE_START):
            src = block_arg_value(mblk["body"], "source")
            if not src or not src.startswith((".", "/")):
                continue
            try:
                target_dir = str((caller_dir / src).resolve())
            except (OSError, ValueError):
                continue
            referenced_dirs.add(target_dir)
    target_root = str(c.target.resolve()) if isinstance(c.target, Path) else ""
    out: list[dict] = []
    for dirkey, first_tf in module_like_dirs.items():
        if dirkey == target_root:
            continue
        if dirkey in referenced_dirs:
            continue
        out.append({
            "id": c.eid,
            "file": first_tf,
            "line": 1,
            "resource": f"<module:{Path(dirkey).name}>",
            "context": (
                f"module dir {dirkey} declares variables/outputs "
                f"but is not referenced by any `module {{ source = ... }}` "
                f"in the scan corpus"
            ),
        })
    return out


@_register_corpus("registry_fingerprint")
def _corpus_registry_fingerprint(c: CorpusCtx) -> list[dict]:
    """``registry_fingerprint`` — module-reuse detector. A directory
    whose resource cluster matches the shape of a public-registry
    module (e.g. ``terraform-aws-modules/vpc/aws``). Fingerprint comes
    from the catalogue entry's top-level ``fingerprint`` block.
    """
    fp = c.entry.get("fingerprint") or {}
    if not fp:
        return []
    out: list[dict] = []
    for finding in _check_registry_fingerprint(fp, c.module_clusters_cache):
        finding["id"] = c.eid
        out.append(finding)
    return out
