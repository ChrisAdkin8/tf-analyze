"""Inbound network exposure — shared model for ``firewall_open_port``.

Parser-migration Step 4 (tasks/hcl-parser-migration.md §10). Every
supported firewall / security-group resource type is reduced to the same
list of inbound rules — sources, port range — so one matcher (and the
structured ``escalation: match: {ports: [...]}``) works across AWS, Azure
and GCP:

* ``aws_security_group`` — ``ingress`` blocks and the ``ingress = [{...}]``
  attribute form (egress is ignored);
* ``aws_security_group_rule`` with ``type = "ingress"``;
* ``aws_vpc_security_group_ingress_rule``;
* ``azurerm_network_security_group`` ``security_rule`` blocks and
  ``azurerm_network_security_rule`` — Inbound + Allow only;
* ``google_compute_firewall`` — ingress direction, one rule per ``allow``.

Values are read through a :class:`TreeView` (parse tree) or, for a file
the parser can't read, a :class:`TextView` with the same lookup rules.
``var.X`` / ``local.X`` references are resolved against the directory's
variable defaults, so ``cidr_blocks = var.open`` with ``default =
["0.0.0.0/0"]`` is seen as world-open.

Pure functions only; no engine state.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from _hcl import (
    _is_block_list,
    _mask_to_top_level,
    _top_level_arg_value,
    single_interpolation,
)

ALL_PORTS = (0, 65535)
# Azure service tags / wildcards that mean "anywhere". CIDRs are checked
# by prefix length in is_world, so every spelling of 0.0.0.0/0 and ::/0
# counts (`0::/0`, `::0/0`, `0000::/0`), not just the two canonical ones.
_AZURE_WORLD = {"*", "internet", "any"}
_ALL_PROTOCOLS = {"-1", "all", "*"}
_REF_RE = re.compile(r"^(var|local)\.([\w-]+)$")
_RANGE_RE = re.compile(r"^\s*(\d+)\s*(?:-\s*(\d+))?\s*$")

SUPPORTED_TYPES = frozenset(
    {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "azurerm_network_security_group",
        "azurerm_network_security_rule",
        "google_compute_firewall",
    }
)


# ---- Views over a resource -------------------------------------------------


class TreeView:
    """Lookups on a parse-tree subtree (``blk["attrs"]``)."""

    def __init__(self, attrs: dict):
        self._attrs = attrs

    def get(self, key: str):
        value = self._attrs.get(key)
        return None if _is_block_list(value) else value

    def blocks(self, name: str) -> list[TreeView]:
        """Nested blocks *and* the list-of-objects attribute form."""
        value = self._attrs.get(name)
        if isinstance(value, dict):
            value = [value]
        if not isinstance(value, list):
            return []
        return [TreeView(v) for v in value if isinstance(v, dict)]


class TextView:
    """Regex-fallback lookups on a block body, with the same top-level
    rules as `TreeView`. (The ``name = [{...}]`` list-of-objects form is
    only seen on the tree path.)"""

    def __init__(self, body: str):
        self._body = body

    def get(self, key: str):
        raw = _top_level_arg_value(self._body, key)
        return None if raw is None else parse_literal(raw)

    def blocks(self, name: str) -> list[TextView]:
        masked = _mask_to_top_level(self._body)
        opener = re.compile(rf"(?m)^[ \t]*{re.escape(name)}[ \t]*(?:=[ \t]*)?\{{")
        out = []
        for m in opener.finditer(masked):
            close = masked.find("}", m.end())
            if close >= 0:
                out.append(TextView(self._body[m.end() : close]))
        return out


def view_for(blk: dict):
    attrs = blk.get("attrs")
    return TreeView(attrs) if attrs is not None else TextView(blk["body"])


# ---- Literals and references -------------------------------------------------


def _scalar(token: str):
    t = token.strip()
    if len(t) >= 2 and t[0] == t[-1] == '"':
        return t[1:-1]
    if t in ("true", "false"):
        return t == "true"
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    return t


def parse_literal(text: str):
    """Parse the HCL text `block_arg_value` returns (strings already
    unquoted at top level) into a Python value: lists of strings /
    numbers / bare references, ``true``/``false``, integers; anything
    else is returned as the string itself."""
    t = text.strip()
    if t.startswith("[") and t.endswith("]"):
        items = re.findall(r'"(?:[^"\\]|\\.)*"|[^,\s\[\]][^,\[\]]*', t[1:-1])
        return [_scalar(i) for i in items if i.strip()]
    return _scalar(t)


def resolve(value, var_defaults: dict, _depth: int = 0):
    """Resolve a plain ``var.X`` / ``local.X`` reference (bare or as a
    single ``${...}``) to its default, recursively and element-wise for
    lists. Anything unresolvable is returned unchanged."""
    if isinstance(value, list):
        out: list = []
        for v in value:
            r = resolve(v, var_defaults, _depth)
            out.extend(r if isinstance(r, list) else [r])
        return out
    if not isinstance(value, str) or _depth > 4:
        return value
    expr = single_interpolation(value)
    m = _REF_RE.match((expr if expr is not None else value).strip())
    if not m:
        return value
    key = m.group(2) if m.group(1) == "var" else "__local__" + m.group(2)
    raw = var_defaults.get(key)
    if raw is None:
        return value
    return resolve(parse_literal(raw), var_defaults, _depth + 1)


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ---- Inbound rules --------------------------------------------------------------


@dataclass(frozen=True)
class InboundRule:
    sources: tuple[str, ...]
    ports: tuple[int, int] | None  # inclusive range; None = unknown

    def covers(self, port: int) -> bool:
        return self.ports is not None and self.ports[0] <= port <= self.ports[1]


def _port_range(lo, hi, protocol) -> tuple[int, int] | None:
    if str(protocol).strip().lower() in _ALL_PROTOCOLS:
        return ALL_PORTS
    try:
        lo_i = int(lo)
        hi_i = int(hi) if hi is not None else lo_i
    except (TypeError, ValueError):
        return None
    if lo_i <= 0 and hi_i in (0, 65535):  # AWS: 0-0 / 0-65535 = all ports
        return ALL_PORTS
    return (lo_i, hi_i)


def _parse_port_spec(spec) -> tuple[int, int] | None:
    """Azure / GCP port strings: ``"22"``, ``"1000-2000"``, ``"*"``."""
    s = str(spec).strip()
    if s in ("*", ""):
        return ALL_PORTS
    m = _RANGE_RE.match(s)
    if not m:
        return None
    lo = int(m.group(1))
    return (lo, int(m.group(2)) if m.group(2) else lo)


def _str_list(view, keys: tuple[str, ...], vd: dict) -> tuple[str, ...]:
    out: list[str] = []
    for k in keys:
        out.extend(str(v) for v in _as_list(resolve(view.get(k), vd)))
    return tuple(out)


def _aws_rule(view, vd: dict, *, cidr_keys, protocol_key) -> InboundRule:
    return InboundRule(
        sources=_str_list(view, cidr_keys, vd),
        ports=_port_range(
            resolve(view.get("from_port"), vd),
            resolve(view.get("to_port"), vd),
            resolve(view.get(protocol_key), vd),
        ),
    )


def _is_not(value, expected: str) -> bool:
    """True only when ``value`` is *known* to differ from ``expected``.

    Fails closed: a missing or unresolvable value (a reference such as
    ``var.rule_type`` with no usable default) might be ``expected`` at
    apply time, so it is not treated as a mismatch — a security scanner
    should report a possibly-open rule rather than drop it.
    """
    if value is None:
        return False
    s = str(value).strip()
    if "${" in s or _REF_RE.match(s) or re.match(r"^(data|module)\.", s):
        return False
    return s.lower() != expected


def _azure_rules(view, vd: dict) -> list[InboundRule]:
    # A missing `direction` / `access` is a provider error, so only a known
    # non-matching value (e.g. "Outbound", "Deny") skips the rule.
    if _is_not(resolve(view.get("direction"), vd), "inbound"):
        return []
    if _is_not(resolve(view.get("access"), vd), "allow"):
        return []
    sources = _str_list(view, ("source_address_prefix", "source_address_prefixes"), vd)
    specs = _as_list(resolve(view.get("destination_port_range"), vd)) + _as_list(
        resolve(view.get("destination_port_ranges"), vd)
    )
    if str(resolve(view.get("protocol"), vd)).strip() == "*" and not specs:
        specs = ["*"]
    return [InboundRule(sources, _parse_port_spec(s)) for s in specs] or [
        InboundRule(sources, None)
    ]


def _gcp_rules(view, vd: dict) -> list[InboundRule]:
    if str(resolve(view.get("direction"), vd) or "INGRESS").upper() == "EGRESS":
        return []
    sources = _str_list(view, ("source_ranges",), vd)
    # Google Cloud: an ingress rule with no source "uses the default source
    # IPv4 address range 0.0.0.0/0" (VPC firewall docs). It used to count
    # as no source at all, so SSH open to everyone was not flagged.
    if not sources and all(
        view.get(k) is None for k in ("source_tags", "source_service_accounts")
    ):
        sources = ("0.0.0.0/0",)
    rules: list[InboundRule] = []
    for allow in view.blocks("allow"):
        protocol = str(resolve(allow.get("protocol"), vd)).lower()
        specs = _as_list(resolve(allow.get("ports"), vd))
        if not specs or protocol in _ALL_PROTOCOLS:
            rules.append(InboundRule(sources, ALL_PORTS))
        else:
            rules.extend(InboundRule(sources, _parse_port_spec(s)) for s in specs)
    return rules


def inbound_rules(resource_type: str, view, var_defaults: dict) -> list[InboundRule]:
    """Every inbound allow rule on one resource, normalised."""
    vd = var_defaults
    if resource_type == "aws_security_group":
        return [
            _aws_rule(
                i,
                vd,
                cidr_keys=("cidr_blocks", "ipv6_cidr_blocks"),
                protocol_key="protocol",
            )
            for i in view.blocks("ingress")
        ]
    if resource_type == "aws_security_group_rule":
        if _is_not(resolve(view.get("type"), vd), "ingress"):
            return []
        return [
            _aws_rule(
                view,
                vd,
                cidr_keys=("cidr_blocks", "ipv6_cidr_blocks"),
                protocol_key="protocol",
            )
        ]
    if resource_type == "aws_vpc_security_group_ingress_rule":
        return [
            _aws_rule(
                view,
                vd,
                cidr_keys=("cidr_ipv4", "cidr_ipv6"),
                protocol_key="ip_protocol",
            )
        ]
    if resource_type == "azurerm_network_security_group":
        return [
            r for rule in view.blocks("security_rule") for r in _azure_rules(rule, vd)
        ]
    if resource_type == "azurerm_network_security_rule":
        return _azure_rules(view, vd)
    if resource_type == "google_compute_firewall":
        return _gcp_rules(view, vd)
    return []


def is_world(source: str, resource_type: str) -> bool:
    s = source.strip()
    if resource_type.startswith("azurerm_") and s.lower() in _AZURE_WORLD:
        return True
    try:
        return ipaddress.ip_network(s, strict=False).prefixlen == 0
    except ValueError:
        return False


def world_open_rules(resource_type: str, view, var_defaults: dict) -> list[InboundRule]:
    """Inbound allow rules whose sources include "anywhere"."""
    return [
        r
        for r in inbound_rules(resource_type, view, var_defaults)
        if any(is_world(s, resource_type) for s in r.sources)
    ]
