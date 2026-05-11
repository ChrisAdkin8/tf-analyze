"""Plan-time and state-time rule evaluation.

Re-runs the catalogue against ``terraform show -json`` output, in two
modes:

* :func:`detect_in_plan` (``--mode plan``) walks ``planned_values`` and
  emits findings tagged ``mode: plan``.
* :func:`detect_in_state` (``--mode drift``, R30.12) walks ``values``
  (the deployed state) and emits findings tagged ``mode: state``. This
  surfaces *drift* — the gap between what the HCL says and what
  ``terraform apply`` actually deployed.

Both share :func:`_evaluate_against_resources`, which loops the
catalogue once and applies every plan-supported rule kind. Pattern
kinds that need raw HCL (regex matches, indentation-aware checks)
aren't plan-supported — those still run via ``detect_in_file`` on the
source text.

Extracted from ``detect.py`` as the **thirteenth modularisation seam**.
The module imports nothing from detect.py — only stdlib — so the test
suite can exercise it in isolation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# Pattern kinds whose evaluation only needs the resolved attribute
# values (no HCL source position, no regex over raw text). Anything
# outside this set is silently skipped in plan/state mode — the rule
# still runs in static mode against the source files.
PLAN_SUPPORTED_KINDS = frozenset({
    "resource_arg",
    "resource_missing_arg",
    "resource_present",
    "hcl_attr",
    "data_source_present",
})


def walk_plan_resources(planned: dict) -> list[dict]:
    """Flatten the plan/state tree into a list of resource dicts.

    Each entry has at minimum: ``address``, ``type``, ``name``,
    ``values``, ``mode``. Resources inside ``child_modules`` are
    inlined; the address keeps the ``module.foo.bar.baz`` prefix so
    the operator can locate the source.
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


def plan_value_at_path(values: dict, path: str):
    """Fetch a dotted path from a resolved values dict.

    The provider's JSON encoding nests blocks as lists of dicts (e.g.
    ``lifecycle: [{prevent_destroy: true}]``), so we traverse
    list-of-dict by taking the first element and continuing.
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


def evaluate_against_resources(
    resources: list[dict],
    entries: list[dict],
    *,
    finding_mode: str,
    file_marker: str,
) -> list[dict]:
    """Re-evaluate plan-supported rule kinds against a flat resource list.

    Factored out so both :func:`detect_in_plan` (``planned_values``)
    and :func:`detect_in_state` (state ``values``) share the inner
    loop. The ``finding_mode`` value lands on each finding's ``mode``
    field; consumers use it to disambiguate plan-time vs state-time
    vs static.
    """
    findings: list[dict] = []
    for entry in entries:
        eid = entry["id"]
        for pat in entry.get("patterns") or []:
            kind = pat.get("kind", "")
            if kind not in PLAN_SUPPORTED_KINDS:
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
                            "file": file_marker,
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": finding_mode,
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
                    val = plan_value_at_path(r.get("values") or {}, arg_path)
                    if val in (None, [], {}):
                        if suppress_if:
                            s_arg = suppress_if.get("arg", "")
                            s_val = suppress_if.get("equals")
                            if s_arg and s_val is not None:
                                actual = plan_value_at_path(r.get("values") or {}, s_arg)
                                if actual is not None and str(actual).lower() == str(s_val).lower():
                                    continue
                        findings.append({
                            "id": eid,
                            "file": file_marker,
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": finding_mode,
                        })
            elif kind == "resource_present":
                rt = pat.get("resource")
                if not rt:
                    continue
                for r in resources:
                    if r.get("type") == rt:
                        findings.append({
                            "id": eid,
                            "file": file_marker,
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": finding_mode,
                        })
            elif kind == "data_source_present":
                dt = pat.get("data_source")
                if not dt:
                    continue
                for r in resources:
                    if r.get("type") == dt and r.get("mode") == "data":
                        findings.append({
                            "id": eid,
                            "file": file_marker,
                            "line": 0,
                            "resource": r.get("address", f"data.{dt}.?"),
                            "mode": finding_mode,
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
                    val = plan_value_at_path(r.get("values") or {}, path)
                    if val is None:
                        continue
                    if not_equal is not None and str(val).lower() != str(not_equal).lower():
                        findings.append({
                            "id": eid,
                            "file": file_marker,
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": finding_mode,
                        })
    return findings


def detect_in_plan(plan_json_path: Path, entries: list[dict]) -> list[dict]:
    """Re-evaluate applicable rules against ``terraform show -json`` plan output.

    Returns the same finding shape as ``detect_in_file`` so the SARIF /
    JSON / markdown emitters need no changes. Findings are tagged with
    ``mode: plan`` so reports can disambiguate plan-time vs static-time
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
    resources = walk_plan_resources(plan.get("planned_values") or {})
    return evaluate_against_resources(
        resources, entries,
        finding_mode="plan",
        file_marker="<plan>",
    )


def detect_in_state(state_json_path: Path, entries: list[dict]) -> list[dict]:
    """Re-evaluate applicable rules against ``terraform show -json`` state output.

    R30.12 — ``tf-analyze drift``. State output's top-level shape is
    ``{"format_version": ..., "values": {"root_module": {...}}}``, so we
    walk ``values`` instead of ``planned_values`` and tag findings with
    ``mode: state`` so reports can distinguish "the static HCL claims X
    but the state file shows Y" from plan/static-time triggers.

    Drift is the gap between intent (the HCL the team wrote) and
    reality (what ``terraform apply`` actually deployed). Catching it
    requires re-running the catalogue against the state file the way
    plan-mode re-runs against the plan file.
    """
    try:
        state = json.loads(state_json_path.read_text())
    except Exception as e:
        print(
            f"ERROR: cannot read state JSON {state_json_path}: {e}",
            file=sys.stderr,
        )
        return []
    # plan.tfplan → planned_values; state.tfstate → values; both share
    # the same {root_module, child_modules} shape underneath.
    root = state.get("values") or {}
    resources = walk_plan_resources(root)
    return evaluate_against_resources(
        resources, entries,
        finding_mode="state",
        file_marker="<state>",
    )
