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
from pathlib import Path

from _hcl import attrs_values_at, render_hcl


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


def _plan_suppressed(spec: dict | None, values: dict) -> bool:
    """Plan/state counterpart of `_handlers_generic._suppressed_by`:
    ``suppress_if: {arg, equals | regex}`` holds when any value at the
    (possibly dotted) `arg` equals the literal, case-insensitively, or
    matches the regex."""
    if not spec or not spec.get("arg"):
        return False
    want = spec.get("equals")
    for actual in plan_values_at(values, spec["arg"]):
        if "regex" in spec:
            if re.search(spec["regex"], str(actual)):
                return True
        elif want is not None and str(actual).lower() == str(want).lower():
            return True
    return False


def _plan_name_selected(pat: dict, r: dict) -> bool:
    """Plan/state counterpart of `_handlers_generic._name_selected`."""
    values = r.get("values") or {}
    names = [
        n for n in (r.get("name") or r.get("address", "").split(".")[-1],
                    values.get("name"), values.get("bucket"))
        if isinstance(n, str)
    ]
    if pat.get("name_regex") and not any(re.search(pat["name_regex"], n) for n in names):
        return False
    if pat.get("name_not_regex") and any(re.search(pat["name_not_regex"], n) for n in names):
        return False
    return True


def _plan_empty(value) -> bool:
    """Plan / state JSON lists every unset attribute as ``null`` and every
    unset nested block as ``[]``, so "present" means present and non-empty
    — unlike static HCL, where an unset argument is simply absent."""
    return value is None or value == [] or value == {}


def plan_has_path(values: dict, path: str, *, every: bool = True) -> bool:
    """Plan counterpart of `_hcl.attrs_has_path`: same walk (blocks are
    lists of dicts, maps are dicts) and the same repeated-block rule —
    every instance must have the rest of the path, or any one with
    ``every=False`` — with `_plan_empty` values counting as absent."""
    head, _, rest = path.partition(".")
    if not isinstance(values, dict) or _plan_empty(values.get(head)):
        return False
    if not rest:
        return True
    value = values[head]
    instances = value if isinstance(value, list) else [value]
    instances = [i for i in instances if isinstance(i, dict)]
    check = all if every else any
    return bool(instances) and check(plan_has_path(i, rest, every=every) for i in instances)


def plan_values_at(values: dict, path: str) -> list[str]:
    """Every non-empty value at ``path`` across all instances, rendered as
    HCL text with `_hcl.render_hcl` — so catalogue regexes see ``true``
    (not Python's ``True``) and ``["a", "b"]`` (not ``['a', 'b']``), as
    they do on the static path."""
    return [render_hcl(v) for v in attrs_values_at(values, path) if not _plan_empty(v)]


_INDEX_RE = re.compile(r'\[[^\]]*\]')


def _module_prefix(address: str) -> str:
    """``module.a.module.b.`` for ``module.a[0].module.b.aws_x.y[1]`` —
    the (index-free) module path an address lives in."""
    parts = _INDEX_RE.sub("", address).split(".")
    return "".join(f"module.{parts[i + 1]}." for i in range(0, len(parts) - 2, 2)
                   if parts[i] == "module")


def config_references(plan: dict) -> dict[str, dict[str, list[str]]]:
    """``{address: {arg: [referenced addresses]}}`` from a plan's
    ``configuration`` section, addresses index-free and module-prefixed.
    Planned values lose references (``bucket = aws_s3_bucket.x.id`` is
    unknown until apply); the configuration keeps them."""
    out: dict[str, dict[str, list[str]]] = {}

    def walk(module: dict | None, prefix: str) -> None:
        for r in (module or {}).get("resources") or []:
            refs = {
                arg: [prefix + ref for ref in (expr or {}).get("references") or []]
                for arg, expr in (r.get("expressions") or {}).items()
                if isinstance(expr, dict)
            }
            out[prefix + r.get("address", "")] = refs
        for name, call in ((module or {}).get("module_calls") or {}).items():
            walk((call or {}).get("module"), f"{prefix}module.{name}.")

    walk((plan.get("configuration") or {}).get("root_module"), "")
    return out


def _has_companion(
    r: dict, spec: dict, resources: list[dict],
    references: dict[str, dict[str, list[str]]],
) -> bool:
    """Plan/state counterpart of `_handlers_generic._has_companion`: a
    resource of type ``spec["resource"]`` in the same module points at `r`
    through its ``spec["via"]`` argument — by equal value (always known in
    state), or by reference in the plan configuration."""
    ctype, via = spec.get("resource"), spec.get("via", "bucket")
    own_addr = _INDEX_RE.sub("", r.get("address", ""))
    own_value = (r.get("values") or {}).get(via)
    module = _module_prefix(own_addr)
    for cand in resources:
        if cand.get("type") != ctype:
            continue
        cand_addr = _INDEX_RE.sub("", cand.get("address", ""))
        if _module_prefix(cand_addr) != module:
            continue
        value = (cand.get("values") or {}).get(via)
        if own_value is not None and value == own_value:
            return True
        if any(ref == own_addr or ref.startswith(own_addr + ".")
               for ref in references.get(cand_addr, {}).get(via, [])):
            return True
    return False


def evaluate_against_resources(
    resources: list[dict],
    entries: list[dict],
    *,
    finding_mode: str,
    file_marker: str,
    references: dict[str, dict[str, list[str]]] | None = None,
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
            # `unless_repo_has`, as on the static path: the account-level
            # resource is in the plan and not `enabled = false`.
            if pat.get("unless_repo_has") and any(
                r.get("type") == pat["unless_repo_has"]
                and (r.get("values") or {}).get("enabled") is not False
                for r in resources
            ):
                continue
            if kind == "resource_arg":
                # Same semantics as the static handler: value at
                # nested_path or (possibly dotted) arg, any instance
                # matching fires, fire_if_absent fires when any instance
                # lacks it.
                rt = pat.get("resource")
                path = pat.get("nested_path") or pat.get("arg")
                regex_str = pat.get("regex")
                not_regex_str = pat.get("not_regex")
                if not (rt and path and (regex_str or not_regex_str)):
                    continue
                regex = re.compile(regex_str) if regex_str else None
                not_regex = re.compile(not_regex_str) if not_regex_str else None
                fire_if_absent = pat.get("fire_if_absent", False)
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    rvalues = r.get("values") or {}
                    if _plan_suppressed(pat.get("suppress_if"), rvalues):
                        continue
                    if not _plan_name_selected(pat, r):
                        continue
                    vals = plan_values_at(rvalues, path)
                    if fire_if_absent and (not vals or not plan_has_path(rvalues, path)):
                        hit = True
                    elif not vals:
                        continue
                    else:
                        hit = any(
                            (regex and regex.search(v))
                            or (not_regex and not not_regex.search(v))
                            for v in vals
                        )
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
                # nested_path first, as on the static path.
                arg_path = pat.get("nested_path") or pat.get("arg")
                if not (rt and arg_path):
                    continue
                suppress_if = pat.get("suppress_if")
                every = pat.get("instances", "all") != "any"
                companion = pat.get("unless_companion")
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    rvals = r.get("values") or {}
                    if not _plan_name_selected(pat, r):
                        continue
                    if companion and _has_companion(
                        r, companion, resources, references or {},
                    ):
                        continue
                    if not plan_has_path(rvals, arg_path, every=every):
                        if _plan_suppressed(suppress_if, rvals):
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
                if not_equal is None:
                    continue
                ne_norm = str(not_equal).strip().strip('"').strip("'").lower()
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    if any(
                        v.strip().strip('"').strip("'").lower() != ne_norm
                        for v in plan_values_at(r.get("values") or {}, path)
                    ):
                        findings.append({
                            "id": eid,
                            "file": file_marker,
                            "line": 0,
                            "resource": r.get("address", f"{rt}.?"),
                            "mode": finding_mode,
                        })
    return findings


class PlanInputError(ValueError):
    """A `--plan-json` / `--state-json` file that cannot be scanned. The
    readers used to print ERROR and return no findings, so a broken or
    wrong-kind file passed a `--fail-on` gate having checked nothing."""


def detect_in_plan(plan_json_path: Path, entries: list[dict]) -> list[dict]:
    """Re-evaluate applicable rules against ``terraform show -json`` plan output.

    Returns the same finding shape as ``detect_in_file`` so the SARIF /
    JSON / markdown emitters need no changes. Findings are tagged with
    ``mode: plan`` so reports can disambiguate plan-time vs static-time
    triggers of the same rule ID.
    """
    # Round-5 audit fix #7 — differentiate "file missing" from
    # "file present but unparseable". The prior broad `except Exception`
    # made both look the same in stderr; an operator running
    # `--plan-json /missing/file.tfplan` saw the same "cannot read"
    # message as one running it on a corrupted JSON, with no signal
    # that the file simply wasn't there.
    try:
        text = plan_json_path.read_text()
    except FileNotFoundError:
        raise PlanInputError(
            f"plan JSON not found: {plan_json_path}. "
            f"Did `terraform show -json` run successfully?"
        )
    except OSError as e:
        raise PlanInputError(
            f"cannot read plan JSON {plan_json_path} (OS error): {e}"
        )
    try:
        plan = json.loads(text)
    except json.JSONDecodeError as e:
        raise PlanInputError(
            f"plan JSON at {plan_json_path} is malformed: {e}. "
            f"First 200 chars: {text[:200]!r}"
        )
    if not isinstance(plan, dict) or "planned_values" not in plan:
        hint = (" It looks like state output: use --state-json."
                if isinstance(plan, dict) and "values" in plan else "")
        raise PlanInputError(
            f"{plan_json_path} is not `terraform show -json` plan output "
            f"(no planned_values).{hint}"
        )
    resources = walk_plan_resources(plan.get("planned_values") or {})
    return evaluate_against_resources(
        resources, entries,
        finding_mode="plan",
        file_marker="<plan>",
        references=config_references(plan),
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
    # Round-5 audit fix #7 — same split as `detect_in_plan` above.
    try:
        text = state_json_path.read_text()
    except FileNotFoundError:
        raise PlanInputError(
            f"state JSON not found: {state_json_path}. "
            f"Did `terraform show -json` run successfully?"
        )
    except OSError as e:
        raise PlanInputError(
            f"cannot read state JSON {state_json_path} (OS error): {e}"
        )
    try:
        state = json.loads(text)
    except json.JSONDecodeError as e:
        raise PlanInputError(
            f"state JSON at {state_json_path} is malformed: {e}. "
            f"First 200 chars: {text[:200]!r}"
        )
    # plan.tfplan → planned_values; state.tfstate → values; both share
    # the same {root_module, child_modules} shape underneath.
    # An empty state has no `values`, so only the wrong kind is refused.
    if not isinstance(state, dict) or ("planned_values" in state and "values" not in state):
        hint = " It looks like plan output: use --plan-json." if isinstance(state, dict) else ""
        raise PlanInputError(
            f"{state_json_path} is not `terraform show -json` state output.{hint}"
        )
    root = state.get("values") or {}
    resources = walk_plan_resources(root)
    return evaluate_against_resources(
        resources, entries,
        finding_mode="state",
        file_marker="<state>",
    )
