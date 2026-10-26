"""Terraform JSON syntax (`*.tf.json`) → equivalent native HCL text.

Every detector works on HCL text, so a `.tf.json` file is scanned by
rendering it as the HCL it stands for and scanning that. Findings keep
the `.tf.json` path. Each rendered line records the JSON line it came
from, and `remap_lines` translates finding lines back afterwards, so
reported lines point into the real file.

JSON syntax has no schema-free way to tell a nested block from an object
attribute. Without provider schemas this module uses the rule Terraform
users actually follow: inside a resource-like body, an object (or a list
of objects) is a nested block unless the key is a well-known map
attribute (`tags`, `labels`, …); `provisioner` / `dynamic` take a label.
`module`, `locals` and `output` bodies hold attributes only.

A string that is exactly one interpolation (``"${aws_s3_bucket.b.arn}"``)
means that expression in Terraform, so it is emitted bare — the form the
rules are written against — provided it is one line with no comment or
heredoc marker and its brackets balance on their own; every other string
is emitted as an HCL string literal. Keys that are not valid
identifiers are dropped rather than spliced into the output, and the
``"//"`` comment property is ignored.
"""

from __future__ import annotations

import bisect
import json
import re
from pathlib import Path

from _hcl import brace_walk, single_interpolation

# ---- position-aware JSON reader ---------------------------------------------
#
# `json.loads` drops positions; we need the line of every key. Nodes are
# tuples: ("obj", [(key, key_line, node), ...], open_line, close_line),
# ("arr", [node, ...], line), ("val", python_value, line).

_WS_RE = re.compile(r"[ \t\r\n]*")
_NUMBER_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_MAX_DEPTH = 200


class _Reader:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0
        self.newlines = [m.start() for m in re.finditer("\n", text)]

    def line(self) -> int:
        return bisect.bisect_left(self.newlines, self.i) + 1

    def ws(self) -> None:
        self.i = _WS_RE.match(self.text, self.i).end()

    def fail(self, msg: str) -> ValueError:
        return ValueError(f"invalid JSON at line {self.line()}: {msg}")

    def value(self, depth: int = 0):
        if depth > _MAX_DEPTH:
            raise self.fail("nested too deeply")
        self.ws()
        line = self.line()
        ch = self.text[self.i : self.i + 1]
        if ch == "{":
            self.i += 1
            items = []
            self.ws()
            if self.text.startswith("}", self.i):
                self.i += 1
                return ("obj", items, line, self.line())
            while True:
                self.ws()
                if not self.text.startswith('"', self.i):
                    raise self.fail("expected a key")
                key_line = self.line()
                key = self.string()
                self.ws()
                if not self.text.startswith(":", self.i):
                    raise self.fail("expected ':'")
                self.i += 1
                items.append((key, key_line, self.value(depth + 1)))
                self.ws()
                if self.text.startswith(",", self.i):
                    self.i += 1
                    continue
                if self.text.startswith("}", self.i):
                    close_line = self.line()
                    self.i += 1
                    return ("obj", items, line, close_line)
                raise self.fail("expected ',' or '}'")
        if ch == "[":
            self.i += 1
            items = []
            self.ws()
            if self.text.startswith("]", self.i):
                self.i += 1
                return ("arr", items, line)
            while True:
                items.append(self.value(depth + 1))
                self.ws()
                if self.text.startswith(",", self.i):
                    self.i += 1
                    continue
                if self.text.startswith("]", self.i):
                    self.i += 1
                    return ("arr", items, line)
                raise self.fail("expected ',' or ']'")
        if ch == '"':
            return ("val", self.string(), line)
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.i):
                self.i += len(word)
                return ("val", val, line)
        m = _NUMBER_RE.match(self.text, self.i)
        if m:
            self.i = m.end()
            return ("val", json.loads(m.group()), line)
        raise self.fail("unexpected character")

    def string(self) -> str:
        try:
            s, self.i = json.decoder.scanstring(self.text, self.i + 1)
        except json.JSONDecodeError as e:
            raise self.fail(e.msg) from None
        return s


def _read(text: str):
    r = _Reader(text.lstrip("\ufeff"))
    node = r.value()
    r.ws()
    if r.i != len(r.text):
        raise r.fail("trailing data")
    return node


# ---- HCL rendering ------------------------------------------------------------

_IDENT_RE = re.compile(r"^[A-Za-z_][\w-]*$")
_UNSAFE_BARE_RE = re.compile(r"[\n\r]|#|//|/\*|<<")
_LABEL_RE = re.compile(r"^[\w-]+$")
# A variable's `type` is an expression; emit it bare only when it is a
# plain type constraint, never arbitrary text.
_TYPE_EXPR_RE = re.compile(r"^[a-z]+(?:\((?:[a-z]+|[a-z]+\([a-z]+\))\))?$")

# Object-valued arguments that are maps, not nested blocks.
_MAP_ATTRS = frozenset(
    {
        "tags",
        "tags_all",
        "labels",
        "user_labels",
        "resource_labels",
        "metadata",
        "annotations",
        "variables",
        "parameters",
        "triggers",
        "app_settings",
        "environment_variables",
        "providers",
        "default",
    }
)
# Nested blocks that carry one label: `provisioner "local-exec" { … }`.
_LABELLED_NESTED = frozenset({"provisioner", "dynamic", "backend"})

# Top-level block kinds → number of labels.
_TOP_LEVEL = {
    "resource": 2,
    "data": 2,
    "module": 1,
    "variable": 1,
    "output": 1,
    "provider": 1,
    "check": 1,
    "locals": 0,
    "terraform": 0,
    "moved": 0,
    "import": 0,
    "removed": 0,
}
# Bodies whose object values are always attributes.
_ATTR_ONLY = frozenset({"module", "locals", "output", "required_providers"})


def _bare_expression(s: str) -> str | None:
    """The expression of a single-interpolation string, when it is safe
    to emit unquoted: one line, no comment or heredoc marker (each of
    those can read differently to the regex fallback, the block lexer and
    the parser), and every bracket in it closes inside it, so it cannot
    end the enclosing block or open a new one."""
    expr = single_interpolation(s)
    if expr is None or not expr.strip():
        return None
    if _UNSAFE_BARE_RE.search(expr):
        return None
    for opens, closes in ("{}", "()", "[]"):
        wrapped = opens + expr + closes
        if brace_walk(wrapped, opens=opens, closes=closes) != len(wrapped):
            return None
    return expr


def _hcl_string(s: str) -> str:
    out = json.dumps(s, ensure_ascii=False)
    # JSON's \b and \f escapes are not HCL escapes.
    return out.replace("\\b", "\\u0008").replace("\\f", "\\u000c")


def _inline(node) -> str:
    kind = node[0]
    if kind == "val":
        v = node[1]
        if isinstance(v, str):
            return _bare_expression(v) or _hcl_string(v)
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        return json.dumps(v)
    if kind == "arr":
        return "[" + ", ".join(_inline(n) for n in node[1]) + "]"
    pairs = [
        f"{k if _IDENT_RE.match(k) else _hcl_string(k)} = {_inline(v)}"
        for k, _l, v in node[1]
        if k != "//"
    ]
    return "{ " + ", ".join(pairs) + " }" if pairs else "{}"


def _value_lines(node, indent: str, line: int) -> list[tuple[str, int]]:
    """A value as rendered lines ``[(text, json_line)]``; the caller puts
    the first after ``key = ``. Objects are written one key per line, as
    HCL is; arrays stay on one line."""
    if node[0] != "obj":
        return [(_inline(node), line)]
    items = [(k, kl, v) for k, kl, v in node[1] if k != "//"]
    if not items:
        return [("{}", line)]
    out = [("{", line)]
    for k, kl, v in items:
        key = k if _IDENT_RE.match(k) else _hcl_string(k)
        sub = _value_lines(v, indent + "  ", kl)
        out.append((f"{indent}  {key} = {sub[0][0]}", kl))
        out.extend(sub[1:])
    out.append((f"{indent}}}", node[3]))
    return out


def _is_objects(node) -> bool:
    if node[0] == "obj":
        return True
    return node[0] == "arr" and bool(node[1]) and all(n[0] == "obj" for n in node[1])


def _is_block_value(key: str, node) -> bool:
    """Whether ``key: node`` in a resource-like body is a nested block.
    A list of objects always is (a map is never a list). An object is,
    unless the key is a well-known map or the object has a key that is
    not an identifier — block bodies only hold identifiers."""
    if node[0] == "arr":
        return _is_objects(node)
    if node[0] != "obj" or key in _MAP_ATTRS:
        return False
    return all(_IDENT_RE.match(k) for k, _kl, _v in node[1] if k != "//")


def _objects(node) -> list:
    """An object, or each object of a list of objects (JSON's way of
    repeating a block)."""
    if node[0] == "obj":
        return [node]
    if node[0] == "arr":
        return [n for n in node[1] if n[0] == "obj"]
    return []


class _Emitter:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.source: list[int] = []  # JSON line of each rendered line

    def emit(self, text: str, line: int) -> None:
        # A bare multi-line expression is several rendered lines, all
        # from the same JSON line.
        for part in text.split("\n"):
            self.lines.append(part)
            self.source.append(line)

    def labelled(
        self,
        kw: str,
        node,
        nlabels: int,
        labels: list[str],
        line: int,
        indent: str,
    ) -> None:
        if nlabels == 0:
            # The first block sits on its key's line; a repeat (JSON's
            # list of bodies) on its own `{`.
            for n, obj in enumerate(_objects(node)):
                head = " ".join([kw] + [_hcl_string(lbl) for lbl in labels])
                self.emit(f"{indent}{head} {{", obj[2] if n else line)
                self.body(obj, indent + "  ", kw)
                self.emit(f"{indent}}}", obj[3])
            return
        for obj in _objects(node):
            for key, key_line, child in obj[1]:
                if key == "//" or not _LABEL_RE.match(key):
                    continue
                self.labelled(kw, child, nlabels - 1, labels + [key], key_line, indent)

    def body(self, obj, indent: str, kind: str) -> None:
        attr_only = kind in _ATTR_ONLY
        for key, key_line, node in obj[1]:
            if key == "//" or not _IDENT_RE.match(key):
                continue
            if (
                kind == "variable"
                and key == "type"
                and node[0] == "val"
                and isinstance(node[1], str)
                and _TYPE_EXPR_RE.match(node[1])
            ):
                self.emit(f"{indent}type = {node[1]}", key_line)
            elif key in _LABELLED_NESTED and _is_objects(node):
                self.labelled(key, node, 1, [], key_line, indent)
            elif not attr_only and _is_block_value(key, node):
                for n, child in enumerate(_objects(node)):
                    self.emit(f"{indent}{key} {{", child[2] if n else key_line)
                    self.body(child, indent + "  ", key)
                    self.emit(f"{indent}}}", child[3])
            else:
                rendered = _value_lines(node, indent, key_line)
                self.emit(f"{indent}{key} = {rendered[0][0]}", key_line)
                for text, line in rendered[1:]:
                    self.emit(text, line)


def tf_json_to_hcl(text: str) -> str:
    """Render a `.tf.json` document as native HCL. Raises ValueError on
    JSON that is invalid or not an object."""
    return tf_json_to_hcl_with_map(text)[0]


def tf_json_to_hcl_with_map(text: str) -> tuple[str, list[int]]:
    """`tf_json_to_hcl`, plus the JSON line of each rendered line
    (index 0 is rendered line 1)."""
    root = _read(text)
    if root[0] != "obj":
        raise ValueError("a .tf.json document must be a JSON object")
    em = _Emitter()
    for key, key_line, node in root[1]:
        nlabels = _TOP_LEVEL.get(key)
        if nlabels is not None:
            em.labelled(key, node, nlabels, [], key_line, "")
    return "\n".join(em.lines) + "\n", em.source


# ---- file helpers ----------------------------------------------------------------


def is_tf_json(path: Path) -> bool:
    return path.name.endswith(".tf.json")


def is_tf_source(path: Path) -> bool:
    """A Terraform configuration file: `*.tf` or `*.tf.json`."""
    return path.suffix == ".tf" or is_tf_json(path)


def tf_source_files(root: Path) -> list[Path]:
    """Every `*.tf` then every `*.tf.json` under `root` (recursive)."""
    return list(root.rglob("*.tf")) + list(root.rglob("*.tf.json"))


# Rendered-line → JSON-line maps of every `.tf.json` read this process,
# keyed by `str(path)` — the form findings carry in `file`.
_LINE_MAPS: dict[str, list[int]] = {}


def read_tf_source(path: Path, read_normalized) -> str:
    """Text to scan for `path`: the file itself for `.tf`, the rendered
    HCL for `.tf.json`. `read_normalized` is `_hcl._read_normalized`."""
    text = read_normalized(path)
    if not is_tf_json(path):
        return text
    hcl, source = tf_json_to_hcl_with_map(text)
    _LINE_MAPS[str(path)] = source
    return hcl


def remap_lines(findings: list[dict]) -> list[dict]:
    """Point `line` / `end_line` of findings in `.tf.json` files at the
    JSON source line. In place; returns `findings`. Lines outside the
    rendered text (e.g. file-level line 1) are left as they are."""
    for f in findings:
        source = _LINE_MAPS.get(str(f.get("file", "")))
        if source is None:
            continue
        for key in ("line", "end_line"):
            n = f.get(key)
            if isinstance(n, int) and 1 <= n <= len(source):
                f[key] = source[n - 1]
    return findings
