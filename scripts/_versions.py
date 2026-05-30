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

from _hcl import brace_walk  # type: ignore


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
            # Audit item 22 — single-element form `~> 3` was previously
            # `continue`d (silent skip), producing a false-negative on
            # any version-gated rule. The Terraform spec treats `~> N`
            # as `>= N.0, < (N+1).0`, the same shape as `~> N.M` with
            # one less precision digit; pad `v` to length-2 before the
            # upper-bound calculation so both forms go through the same
            # branch.
            if len(v) < 2:
                v = v + (0,)
            # `~> X.Y` allows [X.Y, X+1.0). The constraint can reach
            # `min_v` iff the upper bound is strictly above `min_v` —
            # if `min_v >= upper`, every allowed version is below
            # `min_v` and the rule must skip. The lower bound `v`
            # being above `min_v` is irrelevant: `min_v` is a floor
            # for "rule applies", not a required lower edge.
            upper = list(v)
            upper[-1] = 0
            upper[-2] = upper[-2] + 1
            upper_t = tuple(upper)
            a_hi, b_hi = _pad(min_v, upper_t)
            if a_hi >= b_hi:
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
    gate. Walking the full block body fixes that.
    """
    tf_block_re = re.compile(r"(?m)^\s*terraform\s*\{")
    rv_re = re.compile(r'(?m)^\s*required_version\s*=\s*"([^"]+)"')
    for text in all_files_text.values():
        for m in tf_block_re.finditer(text):
            end_after = brace_walk(text, m.end() - 1)
            if end_after is None:
                continue
            rm = rv_re.search(text[m.end():end_after - 1])
            if rm:
                return rm.group(1)
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
