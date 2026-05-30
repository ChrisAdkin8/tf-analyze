"""Policy-as-code DSL — expression evaluator + `kind: policy` evaluation.

A small, safe predicate language over the parsed resource model, so users can
author cross-resource / conditional / aggregate rules as catalogue data instead
of Python. See `docs/policy-dsl.md` and `tasks/policy-dsl-draft.md`.

v1 runs on the existing ("hcl1") regex parser — `resource.attr.<path>` and
`resource.tags.<key>` are resolved on demand from the resource block body via
`block_arg_value`, with best-effort scalar/list/bool coercion. The grammar and
evaluator are parser-agnostic, so a future hcl2-backed attr accessor is a drop-in
swap of `_ResourceView`.

Public surface:
  * ``compile_expr(s)`` — parse an expression string to an AST (raises
    ``SyntaxError`` on malformed input; used by `_catalog` to validate at load).
  * ``evaluate_policy(pat, eid, index)`` — run one ``kind: policy`` pattern over
    the workspace resource index; returns ``[{id, file, line, resource, context}]``.

Safety: the evaluator is a hand-rolled recursive-descent parser + tree walker
over a fixed operator/function set. There is NO ``eval``/``exec`` — catalogue
YAML (including user `--catalog` files) cannot execute arbitrary code.
"""
from __future__ import annotations

import json
import re

from _hcl import block_arg_value, brace_walk, _hcl_object_to_json

# --------------------------------------------------------------------------- #
# Tokeniser
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(
    r"""
      (?P<WS>\s+)
    | (?P<STRING>"(?:[^"\\]|\\.)*")
    | (?P<NUMBER>\d+(?:\.\d+)?)
    | (?P<OP><=|>=|==|!=|<|>|\(|\)|\[|\]|,|:|\.)
    | (?P<NAME>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)


def _tokenize(s: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    pos = 0
    for m in _TOKEN_RE.finditer(s):
        if m.start() != pos:
            raise SyntaxError(f"unexpected character at {pos}: {s[pos:pos+10]!r}")
        pos = m.end()
        if m.lastgroup == "WS":
            continue
        toks.append((m.lastgroup, m.group()))
    if pos != len(s):
        raise SyntaxError(f"unexpected character at {pos}: {s[pos:]!r}")
    toks.append(("EOF", ""))
    return toks


# --------------------------------------------------------------------------- #
# Parser (recursive descent) → AST tuples
# --------------------------------------------------------------------------- #
_CMP_OPS = {"==", "!=", "<", "<=", ">", ">="}


class _Parser:
    def __init__(self, toks: list[tuple[str, str]]):
        self.toks = toks
        self.i = 0

    def _peek(self, k: int = 0):
        idx = self.i + k
        return self.toks[idx] if idx < len(self.toks) else ("EOF", "")

    def _eat(self, val: str | None = None):
        kind, v = self._peek()
        if kind == "EOF" and val is not None:
            raise SyntaxError(f"expected {val!r}, got end of input")
        if val is not None and v != val:
            raise SyntaxError(f"expected {val!r}, got {v!r}")
        if kind != "EOF":
            self.i += 1
        return kind, v

    def parse(self):
        node = self._or()
        if self._peek()[0] != "EOF":
            raise SyntaxError(f"trailing tokens: {self._peek()!r}")
        return node

    def _or(self):
        n = self._and()
        while self._peek() == ("NAME", "or"):
            self._eat()
            n = ("or", n, self._and())
        return n

    def _and(self):
        n = self._not()
        while self._peek() == ("NAME", "and"):
            self._eat()
            n = ("and", n, self._not())
        return n

    def _not(self):
        if self._peek() == ("NAME", "not") and self._peek(1) != ("NAME", "in"):
            self._eat()
            return ("not", self._not())
        return self._comparison()

    def _comparison(self):
        left = self._operand()
        kind, v = self._peek()
        op = None
        if kind == "OP" and v in _CMP_OPS:
            op = v; self._eat()
        elif (kind, v) == ("NAME", "in"):
            op = "in"; self._eat()
        elif (kind, v) == ("NAME", "not") and self._peek(1) == ("NAME", "in"):
            op = "not in"; self._eat(); self._eat()
        elif (kind, v) == ("NAME", "matches"):
            op = "matches"; self._eat()
        if op is None:
            return left
        return ("cmp", op, left, self._operand())

    def _operand(self):
        kind, v = self._peek()
        if kind == "STRING":
            self._eat(); return ("lit", _unquote(v))
        if kind == "NUMBER":
            self._eat(); return ("lit", float(v) if "." in v else int(v))
        if (kind, v) == ("OP", "["):
            return self._list()
        if (kind, v) == ("OP", "("):
            self._eat(); e = self._or(); self._eat(")"); return e
        if kind == "NAME":
            if v in ("true", "false"):
                self._eat(); return ("lit", v == "true")
            if v == "null":
                self._eat(); return ("lit", None)
            if v in ("exists", "all", "none", "count"):
                return self._quantifier()
            if v == "has":
                self._eat(); self._eat("("); p = self._path(); self._eat(")")
                return ("has", p)
            if v in ("resource", "that"):
                return self._path()
        raise SyntaxError(f"unexpected token {self._peek()!r}")

    def _path(self):
        _, root = self._eat()
        segs: list[str] = []
        while self._peek() == ("OP", "."):
            self._eat(".")
            kind, seg = self._eat()
            if kind != "NAME":
                raise SyntaxError("expected a field name after '.'")
            segs.append(seg)
        if not segs:
            raise SyntaxError(f"{root!r} needs at least one .field")
        return ("path", root, segs)

    def _list(self):
        self._eat("[")
        items = []
        while self._peek() != ("OP", "]"):
            items.append(self._operand())
            if self._peek() == ("OP", ","):
                self._eat()
            elif self._peek() != ("OP", "]"):
                raise SyntaxError("expected ',' or ']' in list")
        self._eat("]")
        return ("listlit", items)

    def _quantifier(self):
        _, kw = self._eat()
        self._eat("(")
        tkind, rtype = self._eat()
        if tkind != "NAME":
            raise SyntaxError(f"{kw}(...) needs a resource type, got {rtype!r}")
        pred = body = None
        if self._peek() == ("NAME", "where"):
            self._eat(); pred = self._or()
        if kw != "count" and self._peek() == ("OP", ":"):
            self._eat(); body = self._or()
        self._eat(")")
        return ("quant", kw, rtype, pred, body)


def _unquote(s: str) -> str:
    return s[1:-1].replace('\\"', '"').replace("\\\\", "\\")


_AST_CACHE: dict[str, tuple] = {}


def compile_expr(s: str):
    """Parse an expression string to an AST (cached). Raises SyntaxError."""
    if s not in _AST_CACHE:
        _AST_CACHE[s] = _Parser(_tokenize(s)).parse()
    return _AST_CACHE[s]


# --------------------------------------------------------------------------- #
# Evaluator
# --------------------------------------------------------------------------- #
def _truthy(x) -> bool:
    return x != 0 if isinstance(x, (int, float)) and not isinstance(x, bool) else bool(x)


def _ev(node, env):
    t = node[0]
    if t == "lit":
        return node[1]
    if t == "listlit":
        return [_ev(x, env) for x in node[1]]
    if t == "or":
        return _truthy(_ev(node[1], env)) or _truthy(_ev(node[2], env))
    if t == "and":
        return _truthy(_ev(node[1], env)) and _truthy(_ev(node[2], env))
    if t == "not":
        return not _truthy(_ev(node[1], env))
    if t == "path":
        return _eval_path(node, env)
    if t == "has":
        return _eval_path(node[1], env) is not None
    if t == "cmp":
        return _eval_cmp(node[1], _ev(node[2], env), _ev(node[3], env))
    if t == "quant":
        return _eval_quant(node, env)
    raise RuntimeError(f"unknown node {node!r}")


def _eval_path(node, env):
    _, root, segs = node
    cur = env.get(root)
    for s in segs:
        cur = cur.get(s) if hasattr(cur, "get") else None
    return cur


def _eval_cmp(op, l, r):
    if op == "==":
        return l == r
    if op == "!=":
        return l != r
    if op == "in":
        return l in r if isinstance(r, (list, tuple, set, str)) else False
    if op == "not in":
        return l not in r if isinstance(r, (list, tuple, set, str)) else True
    if op == "matches":
        return isinstance(l, str) and isinstance(r, str) and re.search(r, l) is not None
    if l is None or r is None:
        return False
    try:
        return {"<": l < r, "<=": l <= r, ">": l > r, ">=": l >= r}[op]
    except TypeError:
        return False


def _eval_quant(node, env):
    _, kw, rtype, pred, body = node
    resources = env["_resources"]
    matching = [
        rsc for rsc in resources
        if rsc.get("type") == rtype
        and (pred is None or _truthy(_ev(pred, {**env, "that": rsc})))
    ]
    if kw == "exists":
        return len(matching) > 0
    if kw == "none":
        return len(matching) == 0
    if kw == "count":
        return len(matching)
    if kw == "all":
        return all(_truthy(_ev(body, {**env, "that": rsc})) for rsc in matching)
    raise RuntimeError(kw)


# --------------------------------------------------------------------------- #
# Resource view over the existing (regex / "hcl1") resource index
# --------------------------------------------------------------------------- #
def _coerce(value: str):
    """Best-effort scalar/list/bool coercion of a regex-extracted string so
    numeric/list predicates work on the hcl1 path (e.g. `from_port <= 22`)."""
    if not isinstance(value, str):
        return value
    t = value.strip()
    if t in ("true", "false"):
        return t == "true"
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    if t.startswith("[") and t.endswith("]"):
        try:
            return json.loads(t)
        except Exception:
            return value
    return value


def _nested_block_body(body: str, key: str) -> str | None:
    m = re.search(rf"(?m)^\s*{re.escape(key)}\s*\{{", body)
    if not m:
        return None
    end = brace_walk(body, m.end() - 1)
    return body[m.end():end - 1] if end is not None else None


class _AttrView:
    """`resource.attr.<path>` — resolves attributes on demand from a block body.
    A nested block (`x { ... }`) yields another `_AttrView`; a scalar yields its
    coerced value; an absent key yields None."""
    __slots__ = ("_body",)

    def __init__(self, body: str):
        self._body = body

    def get(self, key: str):
        nested = _nested_block_body(self._body, key)
        if nested is not None:
            return _AttrView(nested)
        v = block_arg_value(self._body, key)
        return _coerce(v) if v is not None else None


def _tags(body: str) -> dict:
    """`resource.tags.<key>` — parse a `tags = { ... }` / `labels = { ... }` map."""
    for attr in ("tags", "labels"):
        raw = block_arg_value(body, attr)
        if raw and raw.strip().startswith("{"):
            d = _hcl_object_to_json(raw)
            if isinstance(d, dict):
                return {k: (v if not isinstance(v, str) else v) for k, v in d.items()}
    return {}


class _ResourceView:
    __slots__ = ("_addr", "_entry")

    def __init__(self, addr: str, entry: dict):
        self._addr = addr
        self._entry = entry

    def get(self, key: str):
        e = self._entry
        if key == "type":
            return e.get("type")
        if key == "name":
            return e.get("name")
        if key == "address":
            return self._addr
        if key == "file":
            return e.get("file")
        if key == "line":
            return e.get("line")
        if key == "attr":
            return _AttrView(e.get("body", ""))
        if key == "tags":
            return _tags(e.get("body", ""))
        if key == "graph":
            return None  # v1 ("hcl1"): graph predicates are phase 2
        return None


# --------------------------------------------------------------------------- #
# Pattern evaluation — the `kind: policy` entry point
# --------------------------------------------------------------------------- #
_INTERP_RE = re.compile(r"\{(resource(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\}")


def _interpolate(template: str, env: dict) -> str:
    def repl(m: re.Match) -> str:
        root, *segs = m.group(1).split(".")
        val = _eval_path(("path", root, segs), env)
        return "" if val is None else str(val)
    return _INTERP_RE.sub(repl, template or "")


def evaluate_policy(pat: dict, eid: str, index: dict) -> list[dict]:
    """Run one ``kind: policy`` pattern over the resource index.

    ``pat`` keys: ``match`` (selector, required), exactly one of ``require`` /
    ``forbid`` (the assertion), and ``description`` (finding text; supports
    ``{resource.<path>}`` interpolation). Returns
    ``[{id, file, line, resource, context}]`` — metadata is enriched downstream
    by ``id``. A malformed expression yields no findings (load-time validation
    in ``_catalog`` is where authors see the syntax error).
    """
    match_src = pat.get("match")
    require_src = pat.get("require")
    forbid_src = pat.get("forbid")
    if not match_src or (require_src is None) == (forbid_src is None):
        return []  # need match + exactly one of require/forbid
    try:
        match_ast = compile_expr(match_src)
        assert_ast = compile_expr(require_src if require_src is not None else forbid_src)
    except SyntaxError:
        return []
    is_require = require_src is not None
    description = pat.get("description", "")

    views = [_ResourceView(addr, e) for addr, e in index.items()]
    out: list[dict] = []
    for view in views:
        env = {"resource": view, "_resources": views, "that": None}
        try:
            if not _truthy(_ev(match_ast, env)):
                continue
            holds = _truthy(_ev(assert_ast, env))
        except Exception:
            continue  # never let one resource's eval abort the scan
        if (not holds) if is_require else holds:
            e = view._entry
            out.append({
                "id": eid,
                "file": e.get("file"),
                "line": e.get("line"),
                "resource": view.get("address"),
                "context": _interpolate(description, env),
            })
    return out
