"""IAM policy statements read from the parse tree.

Both policy forms are reduced to one statement model, so the IAM checks
see the same thing however a policy is written:

* ``data "aws_iam_policy_document"`` — ``statement`` blocks, including
  ``dynamic "statement"`` (folded in by `normalise_attrs`).
* A policy-valued argument (``policy``, ``assume_role_policy``, an
  ``inline_policy`` block's ``policy``) holding ``jsonencode({...})``, a
  heredoc or a quoted JSON string.

The old text path rebuilt ``jsonencode`` arguments as JSON with regexes
and gave up — silently — on the formatter's own style (newline-separated
attributes, no commas) and on any reference (``Resource =
aws_s3_bucket.b.arn``). The parse tree has neither problem.

python-hcl2 renders a ``jsonencode`` argument as JSON text in which each
expression it cannot evaluate becomes a ``"${...}"`` string. That text is
usually valid JSON; when it is not (an expression with quotes in it, such
as a conditional), it is still valid HCL — HCL objects accept ``key:
value`` — so it is parsed again as HCL. Values that are expressions stay
``"${...}"`` strings and never match a literal ``"*"``: a wildcard hidden
behind a variable is not reported (unknown at parse time), which is the
conservative direction for these rules.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from _hcl import brace_walk, normalise_attrs, parse_tf, single_interpolation

_JSONENCODE_RE = re.compile(r"\s*jsonencode\s*\((.*)\)\s*", re.DOTALL)

WILDCARD_ACTIONS = frozenset({"*", "*:*"})

# Read-only Describe* / List* calls: many accept no resource ARN at all
# (ec2:DescribeInstances, s3:ListAllMyBuckets), so `Resource = "*"` is the
# only valid value and must not count as a wildcard grant.
_READ_ONLY_LIST_ACTION = re.compile(r"^[a-z0-9-]+:(?:describe|list)[a-z0-9*]*$")


@dataclass
class Statement:
    """One IAM statement, normalised from either policy form."""

    effect: str = "Allow"
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    principals: list[str] = field(default_factory=list)  # identifier values
    line: int | None = None

    def matches(self, check: str) -> bool:
        """Whether this statement triggers the catalogue ``check``.
        Deny statements never do."""
        if self.effect.lower() == "deny":
            return False
        # IAM action names are case-insensitive: `IAM:*` is `iam:*`.
        actions = [a.lower() for a in self.actions]
        wild_action = any(a in WILDCARD_ACTIONS for a in actions)
        wild_resource = "*" in self.resources and not (
            actions and all(_READ_ONLY_LIST_ACTION.match(a) for a in actions)
        )
        if check == "wildcard_action":
            return wild_action
        if check == "wildcard_resource":
            return wild_resource
        if check == "wildcard_action_and_resource":
            return wild_action and wild_resource
        if check == "wildcard_action_iam":
            return any(a.startswith("iam:") and "*" in a for a in actions)
        if check == "public_principal":
            return "*" in self.principals
        if check == "not_action_or_not_resource":
            return bool(self.not_actions or self.not_resources)
        return False


def _strings(value) -> list[str]:
    """A policy field as a list of strings (a lone string is one item)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


# ---- JSON policy documents --------------------------------------------------


def decode_policy(value) -> dict | None:
    """The policy document a policy-valued argument holds, as a dict, or
    None when it is not analysable here (``data.x.json``, ``file(...)``,
    a variable, invalid JSON)."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    expr = single_interpolation(value)
    if expr is not None:
        m = _JSONENCODE_RE.fullmatch(expr)
        if m is None:
            return None
        arg = m.group(1)
        try:
            doc = json.loads(arg)
        except ValueError:
            tree, _err = parse_tf("x = " + arg + "\n")
            doc = (tree or {}).get("x")
        return doc if isinstance(doc, dict) else None
    try:  # heredoc or quoted JSON string
        doc = json.loads(value)
    except ValueError:
        # A heredoc may hold a bare interpolation as a value
        # (`"Resource": ${jsonencode(var.arns)}`): not JSON, so the whole
        # policy was dropped and a wildcard Action beside it missed. Quote
        # each one (it stays an opaque "${...}" value, as quoted ones are)
        # and try again.
        try:
            doc = json.loads(_quote_bare_interpolations(value))
        except ValueError:
            return None
    return doc if isinstance(doc, dict) else None


def _quote_bare_interpolations(text: str) -> str:
    """`text` with every `${...}` outside a JSON string replaced by that
    interpolation as a JSON string. Nested braces and quotes inside the
    interpolation are matched with `brace_walk`."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
        elif ch == "$" and text.startswith("${", i):
            end = brace_walk(text, i + 1)
            if end is not None:
                out.append(json.dumps(text[i:end]))
                i = end
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def json_statements(doc: dict) -> list[Statement]:
    """Statements of a JSON policy document (``Statement`` may be one
    object or a list)."""
    raw = doc.get("Statement") or []
    if isinstance(raw, dict):
        raw = [raw]
    out: list[Statement] = []
    for st in raw if isinstance(raw, list) else []:
        if not isinstance(st, dict):
            continue
        principal = st.get("Principal")
        if isinstance(principal, dict):
            principals = [v for vals in principal.values() for v in _strings(vals)]
        else:
            principals = _strings(principal)
        effect = st.get("Effect", "Allow")
        out.append(
            Statement(
                effect=effect if isinstance(effect, str) else "Allow",
                actions=_strings(st.get("Action")),
                not_actions=_strings(st.get("NotAction")),
                resources=_strings(st.get("Resource")),
                not_resources=_strings(st.get("NotResource")),
                principals=principals,
            )
        )
    return out


def argument_policies(attrs: dict, args: list[str]) -> list[dict]:
    """Decoded policy documents held by a resource's `args`, including
    the ``policy`` of each ``inline_policy`` block (``aws_iam_role``)."""
    values = [attrs.get(a) for a in args]
    for block in attrs.get("inline_policy") or []:
        if isinstance(block, dict):
            values.append(block.get("policy"))
    return [d for d in (decode_policy(v) for v in values) if d is not None]


# ---- aws_iam_policy_document ------------------------------------------------


def document_statements(body: dict) -> list[Statement]:
    """Statements of a ``data "aws_iam_policy_document"`` subtree."""
    out: list[Statement] = []
    for st in normalise_attrs(body).get("statement") or []:
        if not isinstance(st, dict):
            continue
        principals = [
            ident
            for block in st.get("principals") or []
            if isinstance(block, dict)
            for ident in _strings(block.get("identifiers"))
        ]
        effect = st.get("effect", "Allow")
        out.append(
            Statement(
                effect=effect if isinstance(effect, str) else "Allow",
                actions=_strings(st.get("actions")),
                not_actions=_strings(st.get("not_actions")),
                resources=_strings(st.get("resources")),
                not_resources=_strings(st.get("not_resources")),
                principals=principals,
                line=st.get("__start_line__"),
            )
        )
    return out


def policy_document_subtrees(tree: dict | None) -> dict[str, list[dict]]:
    """``{name: [subtree, ...]}`` for every ``data
    "aws_iam_policy_document"`` block of a parsed file."""
    out: dict[str, list[dict]] = {}
    for item in (tree or {}).get("data") or []:
        if not isinstance(item, dict):
            continue
        for name, body in (item.get("aws_iam_policy_document") or {}).items():
            if isinstance(body, dict):
                out.setdefault(name, []).append(body)
    return out
