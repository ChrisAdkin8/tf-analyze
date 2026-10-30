"""Plan-time and state-time rule evaluation.

Re-runs the catalogue against ``terraform show -json`` output, in two
modes:

* :func:`detect_in_plan` (``--mode plan``) walks ``planned_values`` and
  emits findings tagged ``mode: plan``.
* :func:`detect_in_state` (``--mode drift``, R30.12) walks ``values``
  (the deployed state) and emits findings tagged ``mode: state``. This
  surfaces *drift* — the gap between what the HCL says and what
  ``terraform apply`` actually deployed.

Both share :func:`evaluate_against_resources`, which loops the
catalogue once and applies every plan-supported rule kind. Pattern
kinds that need raw HCL (regex matches, indentation-aware checks)
aren't plan-supported — those still run via ``detect_in_file`` on the
source text.

With no source text to fall back on (a Run Task only has the plan), the
caller passes ``scan_rendered`` and more rules run: the plan's values are
rendered as HCL (:func:`render_resources_hcl`) for the handlers that read
resolved values, and the kinds in `PLAN_ONLY_KINDS` are evaluated here.
Whatever still cannot run is counted by :func:`plan_coverage`, and every
report says so: a plan-only score is a partial score.

Extracted from ``detect.py`` as the **thirteenth modularisation seam**.
The module imports nothing from detect.py — only stdlib — so the test
suite can exercise it in isolation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from _catalog import kubernetes_type_aliases
from _hcl import attrs_values_at, parse_tf, render_hcl
from _tfjson import _hcl_string


# Pattern kinds whose evaluation only needs the resolved attribute
# values (no HCL source position, no regex over raw text). Anything
# outside this set is skipped in plan/state mode when the source files
# are scanned too — the rule runs in static mode against them.
PLAN_SUPPORTED_KINDS = frozenset({
    "resource_arg",
    "resource_missing_arg",
    "resource_present",
    "hcl_attr",
    "data_source_present",
})

# Evaluated here too, but only on a plan / state scan with no source
# files: alongside them these rules already ran in static mode, and would
# report everything twice.
PLAN_ONLY_KINDS = frozenset({"resource_absent", "resource_missing_companion"})

# Kinds whose static handlers judge resolved values, so they give the
# right answer on a plan's values rendered as HCL (`render_resources_hcl`).
# Not every kind does. A rule about how the source is written (hardcoded
# secrets, pinned module sources, variable declarations) cannot be judged:
# `password = var.x` and a literal password look the same in a plan. Nor
# can a kind that follows references (`graph_check`): an unknown value has
# none, and `lifecycle` isn't in a plan at all (`prod_no_deletion_protection`).
PLAN_RENDERED_KINDS = frozenset({
    "deprecated_datasource",
    "firewall_open_port",
    "helm_set_value",
    "iam_json_policy_analysis",
    "iam_policy_analysis",
    "ip_range_span",
    "resource_has_block",
})

# `grep` rules that read a JSON document in a value, not the way the
# source is written. ECS sends `container_definitions` to the API as
# plain text, so a secret in there is a finding wherever it came from.
PLAN_RENDERED_GREP_RULES = frozenset({"SEC-AWS-ECS-001", "SEC-AWS-ECS-002"})


def walk_plan_resources(planned: dict) -> list[dict]:
    """Flatten the plan/state tree into a list of resource dicts.

    Each entry has at minimum: ``address``, ``type``, ``name``,
    ``values``, ``mode``. Resources inside ``child_modules`` are
    inlined; the address keeps the ``module.foo.bar.baz`` prefix so
    the operator can locate the source.
    """
    out: list[dict] = []

    # Plan / state JSON can be hand-edited or produced by other tools, so
    # check each shape rather than trust it: a non-object resource, a
    # non-object ``values`` or a non-list ``child_modules`` used to raise
    # AttributeError / TypeError and exit 1, the "findings found" code.
    def walk(node) -> None:
        if not isinstance(node, dict):
            return
        resources = node.get("resources")
        for r in resources if isinstance(resources, list) else []:
            if not isinstance(r, dict) or not isinstance(r.get("values", {}), (dict, type(None))):
                continue
            if r.get("mode") == "managed" or r.get("mode") is None:
                out.append(r)
        children = node.get("child_modules")
        for cm in children if isinstance(children, list) else []:
            walk(cm)

    walk(planned.get("root_module") if isinstance(planned, dict) else None)
    return out


def walk_plan_data_sources(plan: dict, *roots: str) -> list[dict]:
    """The data sources under each top-level key in `roots`, one per
    address. A data source read during planning (nearly all of them,
    `aws_iam_policy_document` included) is in the plan's ``prior_state``,
    not in ``planned_values``; a state keeps them in ``values``."""
    found: dict[str, dict] = {}

    def walk(node) -> None:
        if not isinstance(node, dict):
            return
        resources = node.get("resources")
        for r in resources if isinstance(resources, list) else []:
            if (isinstance(r, dict) and r.get("mode") == "data"
                    and isinstance(r.get("values") or {}, dict)):
                found.setdefault(str(r.get("address", "")), r)
        children = node.get("child_modules")
        for cm in children if isinstance(children, list) else []:
            walk(cm)

    for root in roots:
        node = plan.get(root) if isinstance(plan, dict) else None
        node = node.get("values") if root == "prior_state" and isinstance(node, dict) else node
        walk(node.get("root_module") if isinstance(node, dict) else None)
    return list(found.values())


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


def _plan_suppressed(spec: dict | list | None, values: dict) -> bool:
    """Plan/state counterpart of `_handlers_generic._suppressed_by`:
    ``suppress_if: {arg, equals | regex}`` holds when any value at the
    (possibly dotted) `arg` equals the literal, case-insensitively, or
    matches the regex; a list of them holds when any one does."""
    if isinstance(spec, list):
        return any(_plan_suppressed(s, values) for s in spec if isinstance(s, dict))
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
            refs["for_each"] = [
                prefix + ref
                for ref in (r.get("for_each_expression") or {}).get("references") or []
            ]
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
    through its ``spec["via"]`` argument (a list means any of them) — by
    equal value (always known in state): `r`'s own value for that argument
    or its ``id`` / ``arn``; or by reference in the plan configuration,
    which counts ``for_each = aws_s3_bucket.x`` too."""
    ctype, via = spec.get("resource"), spec.get("via", "bucket")
    vias = via if isinstance(via, list) else [via]
    own_addr = _INDEX_RE.sub("", r.get("address", ""))
    own = r.get("values") or {}
    module = _module_prefix(own_addr)
    for cand in resources:
        if cand.get("type") != ctype:
            continue
        cand_addr = _INDEX_RE.sub("", cand.get("address", ""))
        if _module_prefix(cand_addr) != module:
            continue
        refs = references.get(cand_addr, {})
        for arg in vias:
            value = (cand.get("values") or {}).get(arg)
            mine = [own.get(k) for k in (arg, "id", "arn")]
            if value is not None and value in mine:
                return True
            if any(ref == own_addr or ref.startswith(own_addr + ".")
                   for ref in [*refs.get(arg, []), *refs.get("for_each", [])]):
                return True
    return False


def evaluate_against_resources(
    resources: list[dict],
    entries: list[dict],
    *,
    finding_mode: str,
    file_marker: str,
    references: dict[str, dict[str, list[str]]] | None = None,
    kinds: frozenset = PLAN_SUPPORTED_KINDS,
    data_sources: list[dict] = (),
) -> list[dict]:
    """Re-evaluate plan-supported rule kinds against a flat resource list.

    Factored out so both :func:`detect_in_plan` (``planned_values``)
    and :func:`detect_in_state` (state ``values``) share the inner
    loop. The ``finding_mode`` value lands on each finding's ``mode``
    field; consumers use it to disambiguate plan-time vs state-time
    vs static. `kinds` adds `PLAN_ONLY_KINDS` on a scan with no source
    files; `data_sources` is what ``data_source_present`` looks at.
    """
    findings: list[dict] = []
    for entry in entries:
        eid = entry["id"]
        for pat in entry.get("patterns") or []:
            kind = pat.get("kind", "")
            if kind not in kinds:
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
                for r in data_sources:
                    if r.get("type") == dt:
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
            elif kind == "resource_absent":
                # As the static handler: once, for the whole plan.
                rt = pat.get("resource")
                if not rt:
                    continue
                present = {r.get("type") for r in resources}
                prerequisite = pat.get("when_present")
                if prerequisite and not present & set(kubernetes_type_aliases(prerequisite)):
                    continue
                if not present & set(kubernetes_type_aliases(rt)):
                    findings.append({
                        "id": eid,
                        "file": file_marker,
                        "line": 0,
                        "resource": f"<absent: {rt}>",
                        "mode": finding_mode,
                    })
            elif kind == "resource_missing_companion":
                rt, ctype, via = pat.get("resource"), pat.get("companion"), pat.get("via")
                if not (rt and ctype and via):
                    continue
                spec = {"resource": ctype, "via": via}
                exempt = pat.get("exempt_if_companion")
                for r in resources:
                    if r.get("type") != rt:
                        continue
                    if _has_companion(r, spec, resources, references or {}):
                        continue
                    if exempt and _has_companion(r, exempt, resources, references or {}):
                        continue
                    findings.append({
                        "id": eid,
                        "file": file_marker,
                        "line": 0,
                        "resource": r.get("address", f"{rt}.?"),
                        "mode": finding_mode,
                    })
    return findings


# ---- Plan values as HCL ------------------------------------------------------

_RENDER_KEY_RE = re.compile(r"^[A-Za-z_][\w-]*$")
_RENDER_LABEL_BAD_RE = re.compile(r"[^\w-]")
_TEMPLATE_RE = re.compile(r"([$%])\{")


def _literal(text: str) -> str:
    """`text` with its ``${`` / ``%{`` escaped: a plan's strings are final
    values, and an IAM policy variable such as ``${aws:username}`` is not
    an interpolation."""
    return _TEMPLATE_RE.sub(r"\1\1{", text)


def _inline_value(value) -> str:
    """A plan value as a one-line HCL expression."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return _literal(_hcl_string(value))
    if isinstance(value, list):
        return "[" + ", ".join(_inline_value(v) for v in value) + "]"
    if isinstance(value, dict):
        pairs = [
            f"{k if _RENDER_KEY_RE.match(k) else _literal(_hcl_string(k))} = {_inline_value(v)}"
            for k, v in value.items()
        ]
        return "{ " + ", ".join(pairs) + " }" if pairs else "{}"
    return "null"


def _json_document(value: str) -> str | None:
    """`value` pretty-printed, when it is a JSON object or list. A plan
    holds ``jsonencode(...)`` as one compact string; the rules read JSON
    documents the way a person writes them, one key per line."""
    if not value.lstrip().startswith(("{", "[")):
        return None
    try:
        return json.dumps(json.loads(value), indent=2, ensure_ascii=False)
    except ValueError:
        return None


def _render_attr(key: str, value, indent: str) -> list[str]:
    """``key = value`` as HCL lines. A JSON document or a multi-line string
    is a heredoc, so its text reads as in a source file."""
    text = value if isinstance(value, str) else None
    document = _json_document(text) if text is not None else None
    if document is None and (text is None or "\n" not in text):
        return [f"{indent}{key} = {_inline_value(value)}"]
    body = (document if document is not None else text).rstrip("\n").replace("\r", "")
    marker = "TF_ANALYZE_EOT"
    while marker in body:
        marker += "_"
    return [f"{indent}{key} = <<{marker}", *_literal(body).split("\n"), marker]


def _render_body(values: dict, indent: str) -> list[str]:
    """A resource's values as HCL lines. Unset attributes (``null``, ``[]``)
    are left out; a list of objects is a repeated nested block, the form
    the provider's schema gives it; any other object is a map."""
    out: list[str] = []
    for key, value in values.items():
        if _plan_empty(value) or not _RENDER_KEY_RE.match(key):
            continue
        if isinstance(value, list) and all(isinstance(v, dict) for v in value):
            for item in value:
                out.append(f"{indent}{key} {{")
                out.extend(_render_body(item, indent + "  "))
                out.append(f"{indent}}}")
        else:
            out.extend(_render_attr(key, value, indent))
    return out


def render_resources_hcl(
    resources: list[dict], data_sources: list[dict] = (),
) -> tuple[str, dict[str, str]]:
    """Plan / state resources as HCL text, and the address of each rendered
    ``type.label`` (``data.type.label`` for a data source). Labels are
    made unique, since instances and modules repeat a name."""
    lines: list[str] = []
    addresses: dict[str, str] = {}

    def block(keyword: str, r: dict, prefix: str) -> None:
        rtype = r.get("type")
        if not isinstance(rtype, str) or not _RENDER_KEY_RE.match(rtype):
            return
        name = _RENDER_LABEL_BAD_RE.sub("_", str(r.get("name") or "r")) or "r"
        label, n = name, 0
        while f"{prefix}{rtype}.{label}" in addresses:
            n += 1
            label = f"{name}__{n}"
        addresses[f"{prefix}{rtype}.{label}"] = str(r.get("address") or f"{prefix}{rtype}.{name}")
        lines.append(f'{keyword} "{rtype}" "{label}" {{')
        lines.extend(_render_body(r.get("values") or {}, "  "))
        lines.append("}")

    for r in resources:
        block("resource", r, "")
    for r in data_sources:
        block("data", r, "data.")
    return "\n".join(lines) + "\n" if lines else "", addresses


def _rendered_entries(entries: list[dict]) -> list[dict]:
    """`entries` cut down to the patterns the rendered text can answer."""
    out = []
    for entry in entries:
        patterns = [p for p in entry.get("patterns") or [] if _renders(entry["id"], p)]
        if patterns:
            out.append({**entry, "patterns": patterns})
    return out


def _renders(rule_id: str, pat: dict) -> bool:
    kind = pat.get("kind", "")
    return kind in PLAN_RENDERED_KINDS or (kind == "grep" and rule_id in PLAN_RENDERED_GREP_RULES)


def _scan_values_as_hcl(
    resources: list[dict],
    data_sources: list[dict],
    entries: list[dict],
    *,
    finding_mode: str,
    file_marker: str,
    scan_rendered: Callable[[str, list[dict]], list[dict]],
) -> list[dict]:
    """Findings of the `PLAN_RENDERED_KINDS` rules on the rendered values,
    filed against `file_marker` and the real address. Text the parser
    refuses would fall back to weaker handlers, so a clean result could
    not be trusted: that is an error, not a pass."""
    rendered = _rendered_entries(entries)
    text, addresses = render_resources_hcl(resources, data_sources)
    if not (text and rendered):
        return []
    error = parse_tf(text)[1]
    if error:
        raise PlanInputError(f"cannot analyse the {file_marker} values: {error}")
    findings = scan_rendered(text, rendered)
    for f in findings:
        f["file"], f["line"], f["mode"] = file_marker, 0, finding_mode
        f["resource"] = addresses.get(f.get("resource", ""), f.get("resource", ""))
    return findings


def plan_coverage(entries: list[dict], source: str) -> dict:
    """What a scan of plan or state values alone (`source`: ``plan`` /
    ``state``), with no source files, covered: how many rules were
    evaluated, partly evaluated (some patterns only) or not evaluated at
    all, and which. Emitted as ``summary.coverage``."""
    ran = PLAN_SUPPORTED_KINDS | PLAN_ONLY_KINDS
    rules = [e for e in entries if e.get("patterns")]
    evaluated = partly = 0
    skipped: list[dict] = []
    for entry in rules:
        hits = [p.get("kind") in ran or _renders(entry["id"], p) for p in entry["patterns"]]
        if all(hits):
            evaluated += 1
        elif any(hits):
            partly += 1
        else:
            skipped.append(entry)
    serious = [e for e in skipped if e.get("default_urgency") in ("CRITICAL", "HIGH")]
    return {
        "partial": True,
        "source": source,
        "rules_total": len(rules),
        "rules_evaluated": evaluated,
        "rules_partly_evaluated": partly,
        "rules_not_evaluated": len(skipped),
        "not_evaluated_critical_high": len(serious),
        "not_evaluated_rules": sorted(e["id"] for e in skipped),
    }


class PlanInputError(ValueError):
    """A `--plan-json` / `--state-json` file that cannot be scanned. The
    readers used to print ERROR and return no findings, so a broken or
    wrong-kind file passed a `--fail-on` gate having checked nothing."""


def detect_in_plan(
    plan_json_path: Path,
    entries: list[dict],
    scan_rendered: Callable[[str, list[dict]], list[dict]] | None = None,
) -> list[dict]:
    """Re-evaluate applicable rules against ``terraform show -json`` plan output.

    Returns the same finding shape as ``detect_in_file`` so the SARIF /
    JSON / markdown emitters need no changes. Findings are tagged with
    ``mode: plan`` so reports can disambiguate plan-time vs static-time
    triggers of the same rule ID.

    `scan_rendered` (``scan(hcl_text, entries)``) marks a scan with no
    source files: the rules that can read the plan's values as HCL run
    through it, and `PLAN_ONLY_KINDS` run here.
    """
    # Round-5 audit fix #7 — differentiate "file missing" from
    # "file present but unparseable". The prior broad `except Exception`
    # made both look the same in stderr; an operator running
    # `--plan-json /missing/file.tfplan` saw the same "cannot read"
    # message as one running it on a corrupted JSON, with no signal
    # that the file simply wasn't there.
    try:
        text = plan_json_path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise PlanInputError(
            f"plan JSON not found: {plan_json_path}. "
            f"Did `terraform show -json` run successfully?"
        )
    except OSError as e:
        raise PlanInputError(
            f"cannot read plan JSON {plan_json_path} (OS error): {e}"
        )
    except UnicodeDecodeError as e:
        raise PlanInputError(f"plan JSON {plan_json_path} is not UTF-8: {e}")
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
    references = config_references(plan)
    if scan_rendered is None:
        return evaluate_against_resources(
            resources, entries,
            finding_mode="plan",
            file_marker="<plan>",
            references=references,
        )
    data_sources = walk_plan_data_sources(plan, "planned_values", "prior_state")
    return evaluate_against_resources(
        resources, entries,
        finding_mode="plan",
        file_marker="<plan>",
        references=references,
        kinds=PLAN_SUPPORTED_KINDS | PLAN_ONLY_KINDS,
        data_sources=data_sources,
    ) + _scan_values_as_hcl(
        resources, data_sources, entries,
        finding_mode="plan",
        file_marker="<plan>",
        scan_rendered=scan_rendered,
    )


def detect_in_state(
    state_json_path: Path,
    entries: list[dict],
    scan_rendered: Callable[[str, list[dict]], list[dict]] | None = None,
) -> list[dict]:
    """Re-evaluate applicable rules against ``terraform show -json`` state output.

    R30.12 — ``tf-analyze drift``. State output's top-level shape is
    ``{"format_version": ..., "values": {"root_module": {...}}}``, so we
    walk ``values`` instead of ``planned_values`` and tag findings with
    ``mode: state`` so reports can distinguish "the static HCL claims X
    but the state file shows Y" from plan/static-time triggers.

    Drift is the gap between intent (the HCL the team wrote) and
    reality (what ``terraform apply`` actually deployed). Catching it
    requires re-running the catalogue against the state file the way
    plan-mode re-runs against the plan file. `scan_rendered`: as for
    :func:`detect_in_plan`.
    """
    # Round-5 audit fix #7 — same split as `detect_in_plan` above.
    try:
        text = state_json_path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise PlanInputError(
            f"state JSON not found: {state_json_path}. "
            f"Did `terraform show -json` run successfully?"
        )
    except OSError as e:
        raise PlanInputError(
            f"cannot read state JSON {state_json_path} (OS error): {e}"
        )
    except UnicodeDecodeError as e:
        raise PlanInputError(f"state JSON {state_json_path} is not UTF-8: {e}")
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
    if scan_rendered is None:
        return evaluate_against_resources(
            resources, entries,
            finding_mode="state",
            file_marker="<state>",
        )
    data_sources = walk_plan_data_sources(state, "values")
    return evaluate_against_resources(
        resources, entries,
        finding_mode="state",
        file_marker="<state>",
        kinds=PLAN_SUPPORTED_KINDS | PLAN_ONLY_KINDS,
        data_sources=data_sources,
    ) + _scan_values_as_hcl(
        resources, data_sources, entries,
        finding_mode="state",
        file_marker="<state>",
        scan_rendered=scan_rendered,
    )
