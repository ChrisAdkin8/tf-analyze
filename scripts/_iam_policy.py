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
    _call_arguments,
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
_MERGE_CALL_RE = re.compile(r"\bmerge\s*\(")
_STATEMENT_KEYS = frozenset({
    "Effect", "Action", "NotAction", "Resource", "NotResource", "Principal", "NotPrincipal",
})
# Control markers beside parsed policy data. Private objects, never strings:
# everything in a policy is text the scanned code chose, so a string marker
# could be written into a policy to turn its analysis off.
_EFFECT_UNKNOWN = object()  # dict key: a merge() whose Effect isn't known
_UNREAD = object()  # dict key: a document with statements left unread
_OBJECTS_CUT = object()  # list item: objects past `_MAX_OBJECTS_TRIED`
_POLICY_FIELD_RE = re.compile(r'\b(?:Statement|Effect)"?\s*[=:]')
# A pathological expression can't turn into one parse per brace for ever.
_MAX_OBJECTS_TRIED = 1000
# Layers of merge() read before giving up with a WARN (`_OBJECTS_CUT`).
_MAX_MERGE_DEPTH = 32

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
    effect_known: bool = True

    def matches(self, check: str) -> bool:
        """Whether this statement triggers the catalogue ``check``.
        Deny statements never do, nor one whose effect is unknown."""
        if not self.effect_known or self.effect.lower() == "deny":
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


def decode_policy(value) -> dict | None:
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
        return doc if isinstance(doc, dict) else _document_in(m.group(1))
    if expr != value.strip():
        if not (len(expr) >= 2 and expr[0] == expr[-1] == '"'):
            return _document_in(expr)
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
            found = _document_in(value)
            return found and {**found, _UNREAD: True}
    return doc if isinstance(doc, dict) else None


def _document_in(text: str) -> dict | None:
    """A document of the statements written out in an expression that isn't
    one itself: ``merge(var.x, {...})``, ``var.a ? jsonencode({...}) : ""``,
    ``tostring(jsonencode({...}))``. None if there are none."""
    statements = _embedded_statements(text)
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


def _keep_escape(m: re.Match) -> str:
    """One `_RAW_QUOTE_RE` match in a string holding an expression, written
    so that decoding the JSON gives back exactly the source text: an
    expression's own strings need their escapes, or text inside one reads
    as code (``"}}, {\\"Effect\\": \\"Deny\\"})"`` turned a real Allow into a
    Deny)."""
    text = m.group()
    if text == '"':
        return '\\"'
    return "\\\\" + ('\\"' if text[1] == '"' else "\\\\" if text[1] == "\\" else text[1])


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
        inner = text[i + 1:end - 1]
        if "${" in inner:
            inner = _RAW_QUOTE_RE.sub(_keep_escape, inner)
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


def _statement_objects(raw, depth: int = 0) -> list:
    """The statement objects of a ``Statement`` value: one object, a list,
    and any in an expression there (``concat(local.b, [{...}])``), found by
    `_embedded_statements`. What the expression adds at apply time is
    unknown, like any other reference."""
    if raw is _OBJECTS_CUT:
        return [raw]
    raw = literal_structure(raw)
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, str):
        return _embedded_statements(raw, depth)
    if isinstance(raw, list):
        return [st for item in raw for st in _statement_objects(item, depth)]
    return []


def _next_object(text: str, start: int) -> tuple[int, str]:
    """Where the next ``{`` or ``merge(`` is in `text`, and which; -1 for
    none."""
    brace = text.find("{", start)
    call = _MERGE_CALL_RE.search(text, start)
    if call and (brace == -1 or call.start() < brace):
        return call.start(), "merge"
    return brace, "{"


def _merge_statements(inner: str, depth: int) -> list:
    """What a ``merge(...)`` call gives, from the text inside its
    parentheses: the merged object, then any object written inside another
    argument. Nested calls are flattened, as they mean the same.

    Only objects written out in the call are known, each key overriding the
    last. Nothing else is followed, not even a `var.X` with a default or a
    `local.X`: a default isn't the value applied, and following references
    is what let a default Deny cancel a real Allow. An unknown argument
    leaves a literal Allow standing, or a written-out admin statement would
    pass; but it could turn a Deny into an Allow, and with no ``Effect`` at
    all could give any, so those are unknown (`_EFFECT_UNKNOWN`). An object
    inside another argument (``tomap({...})``, ``var.x ? {...} : {}``) is
    read as a statement of its own, built on the keys before it and
    overridden by the literals after it."""
    merged: dict = {}
    wrapped: list[dict] = []
    open_ended = False  # an unknown argument since the last `Effect`
    pending = [(arg, 0) for arg in reversed(_call_arguments(inner))]
    while pending:
        arg, level = pending.pop()
        expr = unwrap_value(arg)
        if not expr:
            continue
        call = _MERGE_CALL_RE.match(expr)
        if call and brace_walk(expr, call.end() - 1, opens="(", closes=")") == len(expr):
            if level >= _MAX_MERGE_DEPTH:
                return [_OBJECTS_CUT]
            nested = _call_arguments(expr[call.end():-1])
            pending.extend((a, level + 1) for a in reversed(nested))
            continue
        obj = _jsonencode_argument(expr) if expr.startswith("{") else None
        if isinstance(obj, dict):
            merged.update(obj)
            for st in wrapped:
                st.update(obj)
                if "Effect" in obj:
                    st.pop(_EFFECT_UNKNOWN, None)
            open_ended = open_ended and "Effect" not in obj
            continue
        open_ended = True
        if "{" in expr:
            for st in _embedded_statements(expr, depth + 1):
                if st is _OBJECTS_CUT:
                    return [_OBJECTS_CUT]
                wrapped.append({**merged, **st})
    for st in wrapped:
        if "Effect" not in st:
            st[_EFFECT_UNKNOWN] = True
    if open_ended and ("Effect" not in merged or _effect(merged["Effect"]).lower() == "deny"):
        merged[_EFFECT_UNKNOWN] = True
    return [merged, *wrapped]


def _embedded_statements(text: str, depth: int = 0) -> list:
    """Every statement object written out somewhere in `text`: each
    ``{...}`` that reads as an object, whatever surrounds it, and each
    ``merge(...)`` taken as one object (`_merge_statements`). One that is a
    whole document counts for its statements. An object that doesn't read
    is looked into, for those inside it. Past `_MAX_OBJECTS_TRIED` objects
    or `_MAX_MERGE_DEPTH` layers the rest goes unread, and `_OBJECTS_CUT`
    ends the list. So does a call whose end can't be found: better a WARN
    than a guess at where its arguments stop."""
    if depth > _MAX_MERGE_DEPTH:
        return [_OBJECTS_CUT]
    out: list = []
    i, kind = _next_object(text, 0)
    tries = 0
    while i != -1 and tries < _MAX_OBJECTS_TRIED:
        tries += 1
        if kind == "merge":
            opening = text.index("(", i)
            end = brace_walk(text, opening, opens="(", closes=")")
            if end is None:
                out.append(_OBJECTS_CUT)
                i, kind = _next_object(text, i + 1)
                continue
            found = _merge_statements(text[opening + 1:end - 1], depth)
        else:
            end = brace_walk(text, i)
            found = [_jsonencode_argument(text[i:end])] if end else []
        read = False
        for obj in found:
            if obj is _OBJECTS_CUT or (isinstance(obj, dict) and _STATEMENT_KEYS & obj.keys()):
                out.append(obj)
                read = True
            elif isinstance(obj, dict) and "Statement" in obj:
                out.extend(_statement_objects(obj["Statement"], depth + 1))
                read = True
        i, kind = _next_object(text, end if read else i + 1)
    if i != -1:
        out.append(_OBJECTS_CUT)
    return out


def _unread_statements(doc: dict) -> bool:
    """Whether `doc` has statements written out that could not be read,
    or whose effect is unknown."""
    if _UNREAD in doc:
        return True
    statements = _statement_objects(doc.get("Statement"))
    if any(st is _OBJECTS_CUT or _EFFECT_UNKNOWN in st for st in statements):
        return True
    raw = literal_structure(doc.get("Statement"))
    return any(
        isinstance(item, str) and "{" in unwrap_value(item)
        and not _embedded_statements(item)
        for item in (raw if isinstance(raw, list) else [raw])
    )


def json_statements(doc: dict) -> list[Statement]:
    """Statements of a JSON policy document (``Statement`` may be one
    object or a list)."""
    out: list[Statement] = []
    for st in _statement_objects(doc.get("Statement")):
        if st is _OBJECTS_CUT:
            continue
        principal = literal_structure(st.get("Principal"))
        if isinstance(principal, dict):
            principals = [v for vals in principal.values() for v in _strings(vals)]
        else:
            principals = _strings(principal)
        out.append(
            Statement(
                effect=_effect(st.get("Effect")),
                effect_known=_EFFECT_UNKNOWN not in st,
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


def argument_policies(attrs: dict, args: list[str], where: str = "a resource") -> list[dict]:
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
        doc = decode_policy(value)
        if doc is not None:
            docs.append(doc)
        if (_unread_statements(doc) if doc is not None
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


def text_argument_policies(body: str, args: list[str], where: str = "a resource") -> list[dict]:
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
    return argument_policies(attrs, args, where)


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
