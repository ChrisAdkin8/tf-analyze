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

A construct the parser rejects fails its whole file, usually far from any
policy. The argument or block is then cut out of the text and parsed on
its own (`text_argument_policies`, `document_block_subtree`), so a policy
reads the same as on a clean file.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field

from _hcl import (
    _hcl_object_to_json,
    arg_source,
    block_bodies_at,
    brace_walk,
    normalise_attrs,
    parse_fragment,
    resolve_value_text,
    unwrap_value,
)
from _network import parse_literal

_JSONENCODE_RE = re.compile(r"\s*jsonencode\s*\((.*)\)\s*", re.DOTALL)

WILDCARD_ACTIONS = frozenset({"*", "*:*"})

# The `check` values `Statement.matches` knows; the catalogue loader
# rejects any other (an unknown check would never fire).
CHECKS = frozenset({
    "wildcard_action",
    "wildcard_resource",
    "wildcard_action_and_resource",
    "wildcard_action_iam",
    "public_principal",
    "not_action_or_not_resource",
})

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
        # `Action: "*"` with `NotResource` is every action on every
        # resource bar the few listed: AdministratorAccess in all but name,
        # so it is reported as the admin shape, not a mere wildcard action.
        if wild_action and self.not_resources and not self.resources:
            wild_resource = True
        # A statement with both wildcards is one problem, reported once by
        # `wildcard_action_and_resource`, not three times.
        if check == "wildcard_action":
            return wild_action and not wild_resource
        if check == "wildcard_resource":
            return wild_resource and not wild_action
        if check == "wildcard_action_and_resource":
            return wild_action and wild_resource
        if check == "wildcard_action_iam":
            return any(a.startswith("iam:") and "*" in a for a in actions)
        if check == "public_principal":
            return "*" in self.principals
        if check == "not_action_or_not_resource":
            # An admin-equivalent statement is already reported (once) by
            # `wildcard_action_and_resource`.
            return bool(self.not_actions or self.not_resources) and not (
                wild_action and wild_resource
            )
        return False


def _strings(value) -> list[str]:
    """A policy field as a list of strings (a lone string is one item),
    each literal freed of parentheses and ``${...}``: ``Action = ("*")``
    is ``"*"``, ``actions = (["*"])`` is ``["*"]``."""
    if isinstance(value, str):
        text = resolve_value_text(value, {})
        if text == value:
            return [value]
        literal = parse_literal(text)
        return _strings(literal) if isinstance(literal, list) else [text]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _structure(value):
    """A statement list, statement or principal map that parentheses turned
    into text (``Statement = ([{...}])``), as data; anything else as is."""
    if isinstance(value, str):
        try:
            return ast.literal_eval(unwrap_value(value))
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            pass
    return value


def _effect(value) -> str:
    """A statement's effect; IAM's default when it is not a string."""
    strings = _strings(value)
    return strings[0] if strings else "Allow"


# ---- JSON policy documents --------------------------------------------------


def decode_policy(value) -> dict | None:
    """The policy document a policy-valued argument holds, as a dict, or
    None when it is not analysable here (``data.x.json``, ``file(...)``,
    a variable, invalid JSON). Parentheses and ``${...}`` around any of
    these, however nested, make no difference."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    expr = unwrap_value(value)
    m = _JSONENCODE_RE.fullmatch(expr)
    if m is not None:
        doc = _jsonencode_argument(unwrap_value(m.group(1)))
        return doc if isinstance(doc, dict) else None
    if expr != value.strip():
        if not (len(expr) >= 2 and expr[0] == expr[-1] == '"'):
            return None
        # A string literal behind the wrappers. The parser leaves its
        # escapes in place, or takes them out and leaves the quotes.
        try:
            value = json.loads(expr)
        except ValueError:
            value = expr[1:-1]
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


def _jsonencode_argument(arg: str):
    """The value of a ``jsonencode(...)`` argument: the parser's JSON text,
    the Python repr it prints when the argument has parentheses of its own
    (``jsonencode(({...}))``), or HCL."""
    try:
        return json.loads(arg)
    except ValueError:
        pass
    try:
        return ast.literal_eval(arg)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        tree, _err = parse_fragment("x = " + arg + "\n")
        return (tree or {}).get("x")


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
    raw = _structure(doc.get("Statement")) or []
    if isinstance(raw, dict):
        raw = [raw]
    out: list[Statement] = []
    for st in raw if isinstance(raw, list) else []:
        st = _structure(st)
        if not isinstance(st, dict):
            continue
        principal = _structure(st.get("Principal"))
        if isinstance(principal, dict):
            principals = [v for vals in principal.values() for v in _strings(vals)]
        else:
            principals = _strings(principal)
        out.append(
            Statement(
                effect=_effect(st.get("Effect")),
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


def _decode_source(text: str) -> dict | None:
    """`decode_policy` for an argument's source text. Only the value is
    parsed, so a construct elsewhere in the file cannot stop it; when the
    value itself is what the parser rejects, a ``jsonencode`` argument
    still gets the regex rewrite."""
    expr = unwrap_value(text)
    tree, _err = parse_fragment("__v = " + expr + "\n")
    if tree is not None:
        return decode_policy(tree.get("__v"))
    m = _JSONENCODE_RE.fullmatch(expr)
    return _hcl_object_to_json(m.group(1).strip()) if m else None


def text_argument_policies(body: str, args: list[str]) -> list[dict]:
    """`argument_policies` for a resource without a parse tree, from its
    body text."""
    sources = [arg_source(body, a) for a in args]
    for block in block_bodies_at(body, "inline_policy"):
        sources.append(arg_source(block, "policy"))
    return [d for d in (_decode_source(v) for v in sources if v) if d is not None]


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
        out.append(
            Statement(
                effect=_effect(st.get("effect")),
                actions=_strings(st.get("actions")),
                not_actions=_strings(st.get("not_actions")),
                resources=_strings(st.get("resources")),
                not_resources=_strings(st.get("not_resources")),
                principals=principals,
                line=st.get("__start_line__"),
            )
        )
    return out


def document_block_subtree(name: str, start_line: int, body: str) -> dict | None:
    """The subtree of one ``data "aws_iam_policy_document"`` block, parsed
    on its own from its text (`policy_document_subtrees` needs the whole
    file to parse, and a name to be used once). Blank lines in front keep
    `document_statements` line numbers right for the file. None when the
    block itself does not parse."""
    text = "\n" * (start_line - 1) + f'data "aws_iam_policy_document" "{name}" {{{body}}}\n'
    subtrees = policy_document_subtrees(parse_fragment(text)[0]).get(name)
    return subtrees[0] if subtrees else None


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
