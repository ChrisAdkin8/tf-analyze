#!/usr/bin/env python3
"""Policy-as-code DSL — evaluator SPIKE (not wired into the engine).

De-risks the load-bearing, highest-risk piece of `tasks/policy-dsl-draft.md`:
the expression parser + evaluator. Self-contained stdlib-only (the production
identity), exercised against the draft's §7 worked examples.

Run:  python3 tasks/policy_dsl_spike.py

Scope: the v1 grammar — and/or/not, comparisons (== != < <= > >= in "not in"
matches), `resource.`/`that.` paths, literals, `has(...)`, and the
`exists/all/none/count(TYPE where …)` quantifiers. Graph functions (example d)
are v2 and need the attack graph, so they're out of this spike.

The resource model here is the typed shape "Scope A" would produce
(`attr` is a nested dict, lists are lists, numbers are numbers) — i.e. what the
hcl2-backed accessor feeds the evaluator.
"""
from __future__ import annotations

import re

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
_KEYWORDS = {"and", "or", "not", "in", "matches", "exists", "all", "none",
             "count", "has", "where", "true", "false", "null"}


def tokenize(s: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    pos = 0
    for m in _TOKEN_RE.finditer(s):
        if m.start() != pos:
            raise SyntaxError(f"unexpected char at {pos}: {s[pos:pos+10]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "WS":
            continue
        toks.append((kind, m.group()))
    if pos != len(s):
        raise SyntaxError(f"unexpected char at {pos}: {s[pos:]!r}")
    toks.append(("EOF", ""))
    return toks


# --------------------------------------------------------------------------- #
# Parser (recursive descent) → AST tuples
# --------------------------------------------------------------------------- #
_CMP_OPS = {"==", "!=", "<", "<=", ">", ">="}


class Parser:
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
            raise SyntaxError(f"trailing tokens at {self._peek()!r}")
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
        raise SyntaxError(f"unexpected operand {self._peek()!r}")

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
            raise SyntaxError(f"{root} needs at least one .field")
        return ("path", root, segs)

    def _list(self):
        self._eat("[")
        items = []
        while self._peek() != ("OP", "]"):
            items.append(self._operand())
            if self._peek() == ("OP", ","):
                self._eat()
        self._eat("]")
        return ("listlit", items)

    def _quantifier(self):
        _, kw = self._eat()
        self._eat("(")
        _, rtype = self._eat()           # TYPE
        pred = body = None
        if self._peek() == ("NAME", "where"):
            self._eat(); pred = self._or()
        if kw != "count" and self._peek() == ("OP", ":"):
            self._eat(); body = self._or()
        self._eat(")")
        return ("quant", kw, rtype, pred, body)


def _unquote(s: str) -> str:
    return s[1:-1].replace('\\"', '"').replace("\\\\", "\\")


# --------------------------------------------------------------------------- #
# Evaluator
# --------------------------------------------------------------------------- #
def _truthy(x) -> bool:
    return bool(x) if not isinstance(x, (int, float)) else x != 0


def ev(node, env):
    t = node[0]
    if t == "lit":
        return node[1]
    if t == "listlit":
        return [ev(x, env) for x in node[1]]
    if t == "or":
        return _truthy(ev(node[1], env)) or _truthy(ev(node[2], env))
    if t == "and":
        return _truthy(ev(node[1], env)) and _truthy(ev(node[2], env))
    if t == "not":
        return not _truthy(ev(node[1], env))
    if t == "path":
        return _eval_path(node, env)
    if t == "has":
        return _eval_path(node[1], env) is not None
    if t == "cmp":
        return _eval_cmp(node[1], ev(node[2], env), ev(node[3], env))
    if t == "quant":
        return _eval_quant(node, env)
    raise RuntimeError(f"unknown node {node!r}")


def _eval_path(node, env):
    _, root, segs = node
    cur = env.get(root)
    for s in segs:
        cur = cur.get(s) if isinstance(cur, dict) else None
    return cur


def _eval_cmp(op, l, r):
    if op == "==":
        return l == r
    if op == "!=":
        return l != r
    if op == "in":
        return l in r if isinstance(r, (list, tuple, set)) else False
    if op == "not in":
        return l not in r if isinstance(r, (list, tuple, set)) else True
    if op == "matches":
        return isinstance(l, str) and isinstance(r, str) and re.search(r, l) is not None
    # ordered comparisons — null on either side is False, never a TypeError
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
        and (pred is None or _truthy(ev(pred, {**env, "that": rsc})))
    ]
    if kw == "exists":
        return len(matching) > 0
    if kw == "none":
        return len(matching) == 0
    if kw == "count":
        return len(matching)
    if kw == "all":
        return all(_truthy(ev(body, {**env, "that": rsc})) for rsc in matching)
    raise RuntimeError(kw)


def compile_expr(s: str):
    return Parser(tokenize(s)).parse()


def rule_fires(match: str, kind: str, expr: str, resources: list[dict]) -> list[str]:
    """Return the addresses where `match` binds and the assertion is violated.
    `kind` is 'require' (fires when False) or 'forbid' (fires when True)."""
    m_ast, e_ast = compile_expr(match), compile_expr(expr)
    out = []
    for rsc in resources:
        env = {"resource": rsc, "_resources": resources, "that": None}
        if not _truthy(ev(m_ast, env)):
            continue
        val = _truthy(ev(e_ast, env))
        if (not val) if kind == "require" else val:
            out.append(rsc["address"])
    return out


# --------------------------------------------------------------------------- #
# §7 worked examples — the de-risking assertions
# --------------------------------------------------------------------------- #
def _res(type_, name, attr=None, tags=None):
    return {"type": type_, "name": name, "address": f"{type_}.{name}",
            "file": f"{name}.tf", "line": 1, "attr": attr or {}, "tags": tags or {}}


def demo() -> None:
    checks: list[tuple[str, bool]] = []

    def check(label, got, want):
        ok = sorted(got) == sorted(want)
        checks.append((label, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}: fired={sorted(got)} want={sorted(want)}")

    # (a) cross-resource — RDS must use a CMK with rotation
    rds = [
        _res("aws_db_instance", "good", {"kms_key_id": "aws_kms_key.cmk"}),
        _res("aws_db_instance", "bad", {"kms_key_id": "aws_kms_key.norot"}),
        _res("aws_kms_key", "cmk", {"address": "aws_kms_key.cmk", "enable_key_rotation": True}),
        _res("aws_kms_key", "norot", {"address": "aws_kms_key.norot", "enable_key_rotation": False}),
    ]
    check("(a) RDS→KMS rotation",
          rule_fires('resource.type == "aws_db_instance"', "require",
                     'exists(aws_kms_key where that.attr.address == resource.attr.kms_key_id '
                     'and that.attr.enable_key_rotation == true)', rds),
          ["aws_db_instance.bad"])

    # (b) conditional — prod DBs must block deletion
    dbs = [
        _res("aws_db_instance", "prod_ok", {"deletion_protection": True, "skip_final_snapshot": False}, {"Environment": "prod"}),
        _res("aws_db_instance", "prod_bad", {"deletion_protection": False, "skip_final_snapshot": True}, {"Environment": "prod"}),
        _res("aws_db_instance", "dev", {"deletion_protection": False}, {"Environment": "dev"}),
    ]
    check("(b) prod deletion-protection",
          rule_fires('resource.type == "aws_db_instance" and resource.tags.Environment == "prod"',
                     "require",
                     'resource.attr.deletion_protection == true and resource.attr.skip_final_snapshot != true',
                     dbs),
          ["aws_db_instance.prod_bad"])

    # (c) aggregate — no SSH open to the world
    #   NOTE: the draft §7(c) wrote `cidr_blocks in ["0.0.0.0/0"]` with the
    #   operands reversed — `in` is membership (X in LIST), so it must be
    #   `"0.0.0.0/0" in resource.attr.ingress.cidr_blocks`. Spike caught it.
    sgs = [
        _res("aws_security_group", "open", {"ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}}),
        _res("aws_security_group", "closed", {"ingress": {"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}}),
    ]
    check("(c) SSH open to world",
          rule_fires('resource.type == "aws_security_group"', "forbid",
                     '"0.0.0.0/0" in resource.attr.ingress.cidr_blocks '
                     'and resource.attr.ingress.from_port <= 22 and resource.attr.ingress.to_port >= 22',
                     sgs),
          ["aws_security_group.open"])

    # (e) org guardrail — every aws_ resource must carry a CostCenter tag
    org = [
        _res("aws_instance", "tagged", {}, {"CostCenter": "eng"}),
        _res("aws_instance", "untagged", {}, {}),
        _res("google_compute_instance", "gcp", {}, {}),  # match is ^aws_ → skipped
    ]
    check("(e) mandatory CostCenter tag",
          rule_fires('resource.type matches "^aws_"', "require",
                     'has(resource.tags.CostCenter)', org),
          ["aws_instance.untagged"])

    # robustness: malformed / partial expressions must error cleanly, never crash silently
    for bad in ['resource.', 'exists(', 'resource.a == ', '( resource.a', 'and or']:
        try:
            compile_expr(bad)
            checks.append((f"reject {bad!r}", False))
            print(f"  [FAIL] reject {bad!r}: parsed without error")
        except SyntaxError:
            checks.append((f"reject {bad!r}", True))
            print(f"  [PASS] reject {bad!r}: SyntaxError")

    print()
    passed = sum(1 for _, ok in checks if ok)
    print(f"{passed}/{len(checks)} checks passed")
    if passed != len(checks):
        raise SystemExit(1)


if __name__ == "__main__":
    print("policy-DSL evaluator spike — §7 worked examples\n")
    demo()
