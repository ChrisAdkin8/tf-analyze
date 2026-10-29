"""Provider/Terraform version-constraint helpers.

Extracted from `detect.py` as the second seam in the modularisation
(after `_mitre.py`). Pure functions, no I/O, no engine state — same
shape as `_mitre.py`. Test surface already locked by
`tests/test_a1_improvements.py::test_provider_constraint_allows_truth_table`
which encodes every example in `_provider_constraint_allows`'s docstring
plus the `~> 3.50` regression case.

Public surface:
  * `_version_tuple(s)` — extract a dotted-numeric version tuple.
  * `_provider_constraint_allows(constraint, min_version)` — does the
    user's `version =` constraint admit any version ≥ min_version?
  * `_extract_provider_constraints(all_files_text)` — walk
    `terraform { required_providers {…} }` blocks; returns
    `{provider_name: constraint_string}`.
  * `_extract_terraform_version(all_files_text)` — pull
    `terraform { required_version = "…" }`.
  * `_constraints_by_dir(all_files_text)` — both of the above, per
    folder (one Terraform module), for the folders that declare any.
  * `_entry_applies_to_providers(entry, constraints, tf_constraint)` —
    gate a catalogue entry on its `applies_when:` clause.

Why these go together: every function here either parses a Terraform
constraint string or compares parsed constraints. None reach into
catalogue state, file I/O, or output formatting. They're imported by
`detect.py` for `applies_when` filtering and by `scripts/check_attack_drift.py`
indirectly via the catalogue-load path.

Names are kept underscore-prefixed (`_version_tuple` etc.) because
external callers reference them under those names — preserving the
invariant that the refactor is a no-behaviour-change extraction.
"""
from __future__ import annotations

import re
from pathlib import Path

from _hcl import brace_walk, mask_comments_and_heredocs  # type: ignore


def _version_tuple(s: str) -> tuple[int, ...]:
    """Extract the first dotted-numeric sequence from a string."""
    m = re.search(r"(\d+(?:\.\d+)+)", s)
    if not m:
        m = re.search(r"(\d+)", s)
        if not m:
            return ()
    return tuple(int(x) for x in m.group(1).split("."))


_CLAUSE_RE = re.compile(
    r"^\s*(>=|<=|<|>|~>|!=|=)?\s*v?(\d+(?:\.\d+)*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\s*$"
)


def _pad3(v: tuple) -> tuple:
    """Right-pad a version tuple with zeros (to at least three parts) so
    `1.10`, `1.10.0` compare equal."""
    return v + (0,) * max(0, 3 - len(v))


def _provider_constraint_allows(constraint: str, min_version: str) -> bool:
    """Does the user's `version =` constraint allow any version
    >= `min_version`? The comma-separated clauses (`>=`, `>`, `<`, `<=`,
    `~>`, `=` or a bare version, `!=`) all have to hold at once, so they
    are intersected into one range (plus an exact pin, if any) and the
    answer is "yes" when that range holds a version >= `min_version`.

    An exact pin is satisfied by being at or above the minimum: `= 5.31.0`
    (or a bare `5.31.0`) reaches a `5.0` minimum. (It used to be read as
    "pin equals the minimum", so every exact pin skipped rules with a
    lower minimum.) `~> X.Y` allows `[X.Y, X+1.0)`, `~> X.Y.Z` allows
    `[X.Y.Z, X.Y+1.0)`, and `~> X` is read as `~> X.0`. A pre-release or
    build suffix (`5.0.0-beta1`) is compared by its numbers.

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
      ('5.31.0',           '5.0')  -> True   (exact pin above the minimum)
      ('= 4.9.0',          '5.0')  -> False  (exact pin below it)
      ('',                 '5.0')  -> True   (no constraint = trust user)
    """
    if not constraint:
        return True
    min_v = _version_tuple(min_version)
    if not min_v:
        return True

    lo, lo_incl = _pad3(min_v), True  # the rule needs versions >= min_v
    hi, hi_incl = None, False  # None: no upper bound
    exact: tuple | None = None
    excluded: set[tuple] = set()

    def raise_lo(v: tuple, incl: bool) -> None:
        nonlocal lo, lo_incl
        if v > lo or (v == lo and not incl):
            lo, lo_incl = v, incl

    def lower_hi(v: tuple, incl: bool) -> None:
        nonlocal hi, hi_incl
        if hi is None or v < hi or (v == hi and not incl):
            hi, hi_incl = v, incl

    for raw in constraint.split(","):
        m = _CLAUSE_RE.match(raw)
        if not m:
            continue
        op = m.group(1) or "="
        parts = tuple(int(x) for x in m.group(2).split("."))
        v = _pad3(parts)
        if op == ">=":
            raise_lo(v, True)
        elif op == ">":
            raise_lo(v, False)
        elif op == "<":
            lower_hi(v, False)
        elif op == "<=":
            lower_hi(v, True)
        elif op == "~>":
            # Audit item 22: `~> 3` is `~> 3.0` (>= 3.0, < 4.0).
            if len(parts) < 2:
                parts = parts + (0,)
            raise_lo(_pad3(parts), True)
            upper = list(parts[:-1])
            upper[-1] += 1
            lower_hi(_pad3(tuple(upper)), False)
        elif op == "=":
            if exact is not None and exact != v:
                return False  # two different exact pins: nothing satisfies both
            exact = v
        elif op == "!=":
            excluded.add(v)

    if exact is not None:
        if exact < lo or (exact == lo and not lo_incl):
            return False
        if hi is not None and (exact > hi or (exact == hi and not hi_incl)):
            return False
        return exact not in excluded
    if hi is None or lo < hi:
        return True
    # A single point at most: lo == hi, both inclusive, and not excluded.
    return lo == hi and lo_incl and hi_incl and lo not in excluded


def _extract_provider_constraints(all_files_text: dict) -> dict[str, str]:
    """Walk every file's `terraform { required_providers {...} }` block
    and return the per-provider version constraint string. Last-write-
    wins is fine — most repos define `required_providers` in exactly
    one file (versions.tf), and divergent declarations should be flagged
    by ROB-VERSION-002 separately.

    Comments and heredocs are masked first: a commented-out
    `# azurerm = { version = "~> 2.99" }` or a `/* terraform {...} */`
    block used to override the real pin."""
    constraints: dict[str, str] = {}
    tf_block_re = re.compile(r"(?m)^\s*terraform\s*\{")
    rp_block_re = re.compile(r"required_providers\s*\{")
    entry_re = re.compile(
        r'(\w[\w-]*)\s*=\s*\{[^{}]*?version\s*=\s*"([^"]+)"',
        re.DOTALL,
    )
    for raw in all_files_text.values():
        text = mask_comments_and_heredocs(raw)
        for m in tf_block_re.finditer(text):
            # Quote/comment-aware walk (shared with _extract_terraform_version)
            # so a `}` inside a string in the terraform{} block doesn't
            # truncate the body.
            end_after = brace_walk(text, m.end() - 1)
            if end_after is None:
                continue
            tf_body = text[m.end():end_after - 1]
            rp = rp_block_re.search(tf_body)
            if not rp:
                continue
            for em in entry_re.finditer(tf_body[rp.end():]):
                constraints[em.group(1)] = em.group(2)
    return constraints


def _extract_terraform_version(all_files_text: dict) -> str:
    """Pull the user's `terraform { required_version = "..." }` constraint
    string. First match across files wins; ROB-VERSION-002 already flags
    inconsistent declarations separately.

    The `terraform {}` body is extracted by quote-aware brace matching
    rather than a `[^}]*?` regex: the latter stops at the first nested
    `}`, so the extremely common layout

        terraform {
          backend "s3" { ... }
          required_version = ">= 1.5.0"
        }

    used to return "" and silently disable every `applies_when.min_terraform`
    gate. Walking the full block body fixes that. Comments are masked
    first, so a commented-out `required_version` is not read.
    """
    tf_block_re = re.compile(r"(?m)^\s*terraform\s*\{")
    rv_re = re.compile(r'(?m)^\s*required_version\s*=\s*"([^"]+)"')
    for raw in all_files_text.values():
        text = mask_comments_and_heredocs(raw)
        for m in tf_block_re.finditer(text):
            end_after = brace_walk(text, m.end() - 1)
            if end_after is None:
                continue
            rm = rv_re.search(text[m.end():end_after - 1])
            if rm:
                return rm.group(1)
    return ""


def _constraints_by_dir(all_files_text: dict) -> dict[str, tuple[dict[str, str], str]]:
    """``{folder: (provider_constraints, terraform_constraint)}`` for every
    folder whose files declare a `required_providers` version or a
    `required_version`; keys are ``str(path.parent)``.

    Terraform scopes `required_providers` to one module (one folder), so
    a pin is read per folder: a `modules/legacy/versions.tf` pinning
    `azurerm ~> 2.99` used to be merged into one tree-wide pin and switch
    rules off for the root module too. A folder that declares nothing is
    absent (its findings are not gated)."""
    by_dir: dict[str, dict] = {}
    for fp, text in all_files_text.items():
        by_dir.setdefault(str(Path(fp).parent), {})[fp] = text
    out: dict[str, tuple[dict[str, str], str]] = {}
    for d, files in by_dir.items():
        providers = _extract_provider_constraints(files)
        tf_version = _extract_terraform_version(files)
        if providers or tf_version:
            out[d] = (providers, tf_version)
    return out


def _combine_constraints(a: tuple, b: tuple) -> tuple[dict[str, str], str]:
    """Both of two ``(provider_constraints, terraform_constraint)`` pins at
    once (Terraform must satisfy every module's pin): clauses of the same
    provider are joined with ``,``, which `_provider_constraint_allows`
    reads as "all of these"."""
    providers = dict(a[0])
    for name, c in b[0].items():
        providers[name] = f"{providers[name]}, {c}" if providers.get(name) else c
    tf = ", ".join(x for x in (a[1], b[1]) if x)
    return providers, tf


_NO_PIN: tuple[dict[str, str], str] = ({}, "")
_MAX_ALTERNATIVES = 64


def _effective_constraints(
    own: dict[str, tuple[dict[str, str], str]],
    callers: dict[str, set[str]],
    dirs,
    root: str,
) -> dict[str, list[tuple[dict[str, str], str]]]:
    """For each folder in ``dirs``, the pins it can run under: one
    ``(provider_constraints, terraform_constraint)`` per way it is used.

    A child module runs with the providers its caller's root selected, so
    a folder's pins are its own (``own``, from `_constraints_by_dir`)
    combined with each caller's effective pins (``callers``: folder ->
    the folders that call it as a local module), up the call chain. A
    folder with several callers gets one alternative per caller; the gate
    rules a rule out only when every alternative does, so ambiguity never
    drops a finding. A folder no one calls uses its own pin, or else the
    nearest ancestor folder (up to ``root``) that has one. An entry of
    ``_NO_PIN`` alone means ungated. Folder keys are ``str`` paths in one
    form throughout."""
    memo: dict[str, list] = {}
    active: set[str] = set()

    def eff(d: str) -> list:
        if d in memo:
            return memo[d]
        if d in active:  # a call cycle: nothing more to add
            return [_NO_PIN]
        active.add(d)
        mine = own.get(d, _NO_PIN)
        alts: list = []
        for c in sorted(callers.get(d, ())):
            for alt in eff(c):
                alts.append(_combine_constraints(mine, alt))
        if not alts:
            if d in own:
                alts = [mine]
            else:
                alts = [_NO_PIN]
                p = Path(d)
                while p != p.parent and str(p) != root and _under(str(p), root):
                    p = p.parent
                    if str(p) in own or callers.get(str(p)):
                        alts = eff(str(p))
                        break
        uniq: dict = {}
        for pc, tf in alts:
            uniq.setdefault((tuple(sorted(pc.items())), tf), (pc, tf))
        out = list(uniq.values())
        if len(out) > _MAX_ALTERNATIVES:
            # Too many ways to be used to weigh them all: dropping some
            # could drop the one that allows a rule, so don't gate.
            out = [_NO_PIN]
        active.discard(d)
        memo[d] = out
        return out

    return {d: eff(d) for d in dirs}


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/\\") + "/") \
        or path.startswith(root.rstrip("/\\") + "\\")


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
