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
import sys
from dataclasses import dataclass, field

from _hcl import (
    _NOT_A_LITERAL,
    _hcl_object_to_json,
    _string_end,
    arg_source,
    block_bodies_at,
    brace_walk,
    literal_structure,
    normalise_attrs,
    parse_fragment,
    resolve_value_text,
    unwrap_value,
)
from _network import parse_literal

_JSONENCODE_RE = re.compile(r"\s*jsonencode\s*\((.*)\)\s*", re.DOTALL)

WILDCARD_ACTIONS = frozenset({"*", "*:*"})
# A `merge(...)` statement whose Effect an unresolved argument may set.
_UNKNOWN_EFFECT = "unknown"
_MERGE_CALL_RE = re.compile(r"\bmerge\(")
_STATEMENT_KEYS = frozenset({
    "Effect", "Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal",
})
_EFFECT_UNKNOWN_KEY = "__effect_unknown__"
_OBJECTS_CUT_KEY = "__objects_cut__"
_POLICY_FIELD_RE = re.compile(r'\b(?:Statement|Effect)"?\s*[=:]')
# A pathological expression can't turn into one parse per brace for ever.
_MAX_OBJECTS_TRIED = 1000

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
        Deny statements never do, nor one whose effect is unknown."""
        if self.effect.lower() in ("deny", _UNKNOWN_EFFECT):
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


def _effect(value) -> str:
    """A statement's effect; IAM's default when it is not a string."""
    strings = _strings(value)
    return strings[0] if strings else "Allow"


# ---- JSON policy documents --------------------------------------------------


def decode_policy(value, var_defaults: dict | None = None) -> dict | None:
    """The policy document a policy-valued argument holds, as a dict, or
    None when it is not analysable here (``data.x.json``, ``file(...)``,
    a variable, invalid JSON). Parentheses and ``${...}`` around any of
    these, however nested, make no difference."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    if value.startswith("${"):
        # The parser doubles a backslash that escapes a quote in an
        # expression, which ends the string early for anything reading it.
        value = value.replace('\\\\"', '\\"')
    expr = unwrap_value(value)
    m = _JSONENCODE_RE.fullmatch(expr)
    if m is not None:
        doc = _jsonencode_argument(unwrap_value(m.group(1)))
        return doc if isinstance(doc, dict) else _document_in(m.group(1), var_defaults)
    if expr != value.strip():
        if not (len(expr) >= 2 and expr[0] == expr[-1] == '"'):
            return _document_in(expr, var_defaults)
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
            # Malformed, or a template (`%{ if }`). Whatever else it holds
            # went unread, so say so even when a statement is found.
            found = _document_in(value, var_defaults)
            return found and {**found, "__unread__": True}
    return doc if isinstance(doc, dict) else None


def _document_in(text: str, var_defaults: dict | None) -> dict | None:
    """A document of the statements written out in an expression that isn't
    one itself: ``merge(var.x, {...})``, ``var.a ? jsonencode({...}) : ""``,
    ``tostring(jsonencode({...}))``. None if there are none."""
    statements = _embedded_statements(text, var_defaults)
    return {"Statement": statements} if statements else None


def _jsonencode_argument(arg: str):
    """The value of a ``jsonencode(...)`` argument: the parser's JSON text,
    the same with `_escape_expression_quotes`, the Python repr it prints
    when the argument has parentheses of its own (``jsonencode(({...}))``),
    or HCL."""
    try:
        for text in (arg, _escape_expression_quotes(arg)):
            try:
                return json.loads(text, strict=False)
            except ValueError:
                pass
    except RecursionError:
        pass
    try:
        return ast.literal_eval(arg)
    except _NOT_A_LITERAL:
        tree, _err = parse_fragment("x = " + arg + "\n")
        return (tree or {}).get("x")


_RAW_QUOTE_RE = re.compile(r'\\.|"', re.DOTALL)


def _escape_expression_quotes(text: str) -> str:
    """`text` with each string's inner quotes escaped. The parser prints an
    expression as a ``"${...}"`` string without escaping the expression's
    own quotes: ``"Sid": "${format("s-%s", var.n)}"``. A list or object in
    an expression comes out with Python's quotes instead, so both kinds in
    one policy made it neither JSON, Python nor HCL, and one odd field lost
    every statement beside it."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] != '"':
            out.append(text[i])
            i += 1
            continue
        end = _string_end(text, i)
        inner = _RAW_QUOTE_RE.sub(
            lambda m: '\\"' if m.group() == '"' else m.group(), text[i + 1:end - 1],
        )
        out.append(f'"{inner}"')
        i = end
    return "".join(out)


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


def _statement_objects(raw, var_defaults: dict | None = None) -> list[dict]:
    """The statement objects of a ``Statement`` value: one object, a list,
    and any in an expression there (``concat(local.b, [{...}])``), found by
    `_embedded_statements`. What the expression adds at apply time is
    unknown, like any other reference."""
    raw = literal_structure(raw)
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, str):
        return _embedded_statements(raw, var_defaults)
    if isinstance(raw, list):
        return [st for item in raw for st in _statement_objects(item, var_defaults)]
    return []


def _next_object(text: str, start: int) -> tuple[int, str]:
    """Where the next ``{`` or ``merge(`` is in `text`, and which; -1 for
    none."""
    brace = text.find("{", start)
    call = _MERGE_CALL_RE.search(text, start)
    if call and (brace == -1 or call.start() < brace):
        return call.start(), "merge"
    return brace, "{"


def _call_arguments(text: str) -> list[str]:
    """The top-level arguments of the text inside a call's parentheses."""
    out: list[str] = []
    depth, start, i, n = 0, 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i = _string_end(text, i)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(text[start:i])
            start = i + 1
        i += 1
    return [*out, text[start:]]


def _merged_object(args: list[str], var_defaults: dict | None) -> dict:
    """What ``merge(...)`` of `args` gives: the objects in order, a later
    key winning, as Terraform does; `var.X` / `local.X` are resolved where
    known. An ``Effect`` written out stands unless a later known object
    overrides it: an unknown argument never removes one, or a written-out
    admin statement would pass. Only when no argument gives one is it
    unknown (`_EFFECT_UNKNOWN_KEY`)."""
    merged: dict = {}
    unresolved = False
    for arg in args:
        expr = unwrap_value(resolve_value_text(arg.strip(), var_defaults or {}))
        call = _MERGE_CALL_RE.match(expr)
        if call and expr.endswith(")"):
            obj = _merged_object(_call_arguments(expr[call.end():-1]), var_defaults)
        elif expr.startswith("{"):
            obj = _jsonencode_argument(expr)
        else:
            obj = None
        if isinstance(obj, dict):
            merged.update(obj)
        else:
            unresolved = True
    if unresolved and "Effect" not in merged:
        merged[_EFFECT_UNKNOWN_KEY] = True
    return merged


def _embedded_statements(text: str, var_defaults: dict | None = None) -> list[dict]:
    """Every statement object written out somewhere in `text`: each
    ``{...}`` that reads as an object, whatever surrounds it, and each
    ``merge(...)`` taken as one object (`_merged_object`). One that is a
    whole document counts for its statements. An object that doesn't read
    is looked into, for those inside it. Past `_MAX_OBJECTS_TRIED` the rest
    goes unread, marked with an `_OBJECTS_CUT_KEY` entry."""
    out: list[dict] = []
    i, kind = _next_object(text, 0)
    tries = 0
    while i != -1 and tries < _MAX_OBJECTS_TRIED:
        tries += 1
        if kind == "merge":
            opening = text.index("(", i)
            end = brace_walk(text, opening, opens="(", closes=")")
            obj = _merged_object(_call_arguments(text[opening + 1:end - 1]), var_defaults) if end else None
        else:
            end = brace_walk(text, i)
            obj = _jsonencode_argument(text[i:end]) if end else None
        if isinstance(obj, dict) and _STATEMENT_KEYS & obj.keys():
            out.append(obj)
        elif isinstance(obj, dict) and "Statement" in obj:
            out.extend(_statement_objects(obj["Statement"], var_defaults))
        else:
            i, kind = _next_object(text, i + 1)
            continue
        i, kind = _next_object(text, end)
    if i != -1:
        out.append({_OBJECTS_CUT_KEY: True})
    return out


def _unread_statements(doc: dict, var_defaults: dict | None = None) -> bool:
    """Whether `doc` has statements written out that could not be read,
    or whose effect is unknown."""
    if doc.get("__unread__"):
        return True
    statements = _statement_objects(doc.get("Statement"), var_defaults)
    if any(_EFFECT_UNKNOWN_KEY in st or _OBJECTS_CUT_KEY in st for st in statements):
        return True
    raw = literal_structure(doc.get("Statement"))
    return any(
        isinstance(item, str) and "{" in unwrap_value(item)
        and not _embedded_statements(item, var_defaults)
        for item in (raw if isinstance(raw, list) else [raw])
    )


def json_statements(doc: dict, var_defaults: dict | None = None) -> list[Statement]:
    """Statements of a JSON policy document (``Statement`` may be one
    object or a list). `var_defaults` resolves what a ``merge(...)``
    statement is built from."""
    out: list[Statement] = []
    for st in _statement_objects(doc.get("Statement"), var_defaults):
        if _OBJECTS_CUT_KEY in st:
            continue
        principal = literal_structure(st.get("Principal"))
        if isinstance(principal, dict):
            principals = [v for vals in principal.values() for v in _strings(vals)]
        else:
            principals = _strings(principal)
        out.append(
            Statement(
                effect=_UNKNOWN_EFFECT if _EFFECT_UNKNOWN_KEY in st else _effect(st.get("Effect")),
                actions=_strings(st.get("Action")),
                not_actions=_strings(st.get("NotAction")),
                resources=_strings(st.get("Resource")),
                not_resources=_strings(st.get("NotResource")),
                principals=principals,
            )
        )
    return out


def _is_written_out(value) -> bool:
    """Whether a policy value holds a document in the source itself, so
    failing to decode it is a miss. ``data.x.json``, ``file(...)`` or
    ``jsonencode(var.p)`` hold none: those are unknown here, not unread."""
    if not isinstance(value, str):
        return False
    expr = unwrap_value(value)
    m = _JSONENCODE_RE.fullmatch(expr)
    if m is not None:
        expr = unwrap_value(m.group(1))
    return expr.lstrip('"').startswith("{") or bool(_POLICY_FIELD_RE.search(expr))


_UNDECODED_WARNED: set[str] = set()


def _warn_undecoded(where: str) -> None:
    """Say that a policy went unread, once per place (each rule asks)."""
    if where not in _UNDECODED_WARNED:
        _UNDECODED_WARNED.add(where)
        print(f"WARN: {where}: policy could not be decoded; it was not checked",
              file=sys.stderr)


def argument_policies(attrs: dict, args: list[str], where: str = "a resource",
                      var_defaults: dict | None = None) -> list[dict]:
    """Decoded policy documents held by a resource's `args`, including
    the ``policy`` of each ``inline_policy`` block (``aws_iam_role``). A
    written-out document that can't be decoded gets a WARN naming
    `where`."""
    values = [attrs.get(a) for a in args]
    for block in attrs.get("inline_policy") or []:
        if isinstance(block, dict):
            values.append(block.get("policy"))
    docs: list[dict] = []
    for value in values:
        doc = decode_policy(value, var_defaults)
        if doc is not None:
            docs.append(doc)
        if (_unread_statements(doc, var_defaults) if doc is not None
                else _is_written_out(value)):
            _warn_undecoded(where)
    return docs


def _source_value(text: str | None):
    """The value an argument's source text parses to, alone, so a construct
    elsewhere in the file cannot stop it. When the value itself is what the
    parser rejects, a ``jsonencode`` argument gets the regex rewrite, and
    anything else stays text."""
    if text is None:
        return None
    expr = unwrap_value(text)
    tree, _err = parse_fragment("__v = " + expr + "\n")
    if tree is not None:
        return tree.get("__v")
    m = _JSONENCODE_RE.fullmatch(expr)
    return (_hcl_object_to_json(m.group(1).strip()) if m else None) or expr


def text_argument_policies(body: str, args: list[str], where: str = "a resource",
                           var_defaults: dict | None = None) -> list[dict]:
    """`argument_policies` for a resource without a parse tree: the same
    attributes, read from its body text."""
    attrs = {a: _source_value(arg_source(body, a)) for a in args}
    blocks = block_bodies_at(body, "inline_policy")
    if blocks:
        attrs["inline_policy"] = [
            {"policy": _source_value(arg_source(b, "policy"))} for b in blocks
        ]
    else:  # `inline_policy = [{...}]`
        listed = literal_structure(_source_value(arg_source(body, "inline_policy")))
        attrs["inline_policy"] = listed if isinstance(listed, list) else []
    return argument_policies(attrs, args, where, var_defaults)


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


def document_block_statements(name: str, start_line: int, body: str) -> list[Statement] | None:
    """Statements of one ``data "aws_iam_policy_document"`` block, parsed
    on its own from its text (`policy_document_subtrees` needs the whole
    file to parse, and a name to be used once), with line numbers for the
    file. None when the block itself does not parse."""
    tree = parse_fragment(f'data "aws_iam_policy_document" "{name}" {{{body}}}\n')[0]
    subtrees = policy_document_subtrees(tree).get(name)
    if not subtrees:
        return None
    statements = document_statements(subtrees[0])
    for st in statements:
        if st.line:
            st.line += start_line - 1
    return statements


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
