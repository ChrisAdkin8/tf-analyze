"""Blast-radius analysis — "what could a single `terraform apply` destroy?"

Reuses the attack-graph DAG built by `_attack_graph.build_attack_graph`.
The same edge direction works for both attack propagation and destroy
propagation: if `aws_subnet` references `aws_vpc.id`, attack-graph edges
go ``aws_vpc → aws_subnet`` (compromise spreads downward), and that is
also the destroy direction (`aws_vpc` going away leaves `aws_subnet`
broken).

Three exports:

* :func:`compute_blast_radius` — for each node, count *unique* downstream
  resources reachable via outgoing edges (BFS, cycle-safe).
* :func:`annotate_findings_with_blast_radius` — mutate findings in place
  to carry a ``blast_radius`` integer. Findings whose resource isn't in
  the graph get ``blast_radius: 0``.
* :func:`top_blast_radius_resources` — top-N report payload sorted
  descending by blast radius. Skips the synthetic INTERNET node and
  zero-blast nodes (leaf resources nothing depends on).

The CLI surface (``--blast-radius``), the JSON top-level
``blast_radius`` block, the SARIF ``properties.blastRadius`` per
result, and the demo paste-and-scan UI all read from these helpers.

This module is pure-functional — no I/O, no globals — so it's
straightforward to unit-test in isolation (``tests/test_blast_radius.py``).
"""
from __future__ import annotations

from typing import Iterable


# Synthetic node added by the attack-graph builder. It's an analysis
# convenience, not a real Terraform resource, so we exclude it from
# blast-radius rankings — nobody ever asked "what does the internet
# itself blow up?"
_SYNTHETIC_NODE_IDS = frozenset({"INTERNET"})


def compute_blast_radius(graph: dict) -> dict[str, int]:
    """For every node, count distinct downstream nodes via outgoing edges.

    The result is the number of *other* nodes that would be affected
    (destroyed, plan-changed, or otherwise re-applied) if this one were
    destroyed and recreated. The node itself is not counted.

    BFS over an adjacency map built from ``graph["edges"]``; cycles
    are handled by a ``visited`` set so the count never inflates beyond
    ``len(nodes) - 1``.

    Returns ``{node_id: count}`` for every node in ``graph["nodes"]``,
    including the synthetic INTERNET node (caller can filter).
    """
    node_ids = {n["id"] for n in graph.get("nodes") or []}
    adj: dict[str, list[str]] = {nid: [] for nid in node_ids}
    for edge in graph.get("edges") or []:
        src = edge.get("from")
        dst = edge.get("to")
        if src in adj and dst in node_ids:
            adj[src].append(dst)

    counts: dict[str, int] = {}
    for start in node_ids:
        visited: set[str] = set()
        stack: list[str] = list(adj[start])
        while stack:
            cur = stack.pop()
            if cur in visited or cur == start:
                continue
            visited.add(cur)
            stack.extend(adj.get(cur, ()))
        counts[start] = len(visited)
    return counts


def annotate_findings_with_blast_radius(
    findings: list[dict],
    blast: dict[str, int],
) -> None:
    """Mutate each finding to carry a ``blast_radius`` integer.

    A finding's blast radius is the downstream count of the resource it
    cites. Findings on resources outside the graph (workspace-wide
    findings, file-level findings without a ``resource`` address) get
    ``blast_radius: 0`` so the field is always populated — downstream
    consumers don't have to special-case "missing" vs "zero".
    """
    for f in findings:
        addr = f.get("resource") or ""
        f["blast_radius"] = int(blast.get(addr, 0))


def top_blast_radius_resources(
    graph: dict,
    blast: dict[str, int],
    top_n: int = 10,
    min_radius: int = 1,
) -> list[dict]:
    """Top-N highest-blast-radius resources for the dedicated report panel.

    Returns shape suitable for direct JSON serialisation:

    .. code-block:: python

       [
         {"resource": "aws_vpc.main", "type": "network",
          "file": "vpc.tf", "line": 12,
          "blast_radius": 8, "is_crown_jewel": False,
          "internet_reachable": False},
         ...
       ]

    Filters:

    * synthetic INTERNET node (always excluded)
    * nodes with ``blast_radius < min_radius`` (default 1 — leaf
      resources nothing depends on aren't interesting)

    Ties are broken by node id to keep output deterministic across runs
    (important for golden-file tests and per-SHA caching).
    """
    nodes_by_id = {n["id"]: n for n in graph.get("nodes") or []}
    candidates: list[tuple[str, int]] = [
        (nid, blast.get(nid, 0))
        for nid in nodes_by_id
        if nid not in _SYNTHETIC_NODE_IDS and blast.get(nid, 0) >= min_radius
    ]
    candidates.sort(key=lambda t: (-t[1], t[0]))
    out: list[dict] = []
    for nid, radius in candidates[:top_n]:
        n = nodes_by_id[nid]
        out.append({
            "resource": nid,
            "type": n.get("type", "unknown"),
            "file": n.get("file", ""),
            "line": n.get("line", 0),
            "blast_radius": radius,
            "is_crown_jewel": bool(n.get("is_crown_jewel", False)),
            "internet_reachable": bool(n.get("internet_reachable", False)),
        })
    return out


def render_blast_radius_text(top: Iterable[dict]) -> str:
    """Human-readable table for ``--format text``. Empty input → "".

    Width is bounded so the table doesn't wrap in a typical PR-summary
    or terminal column count.
    """
    rows = list(top)
    if not rows:
        return ""
    lines = [
        "## Blast radius",
        "",
        "Resources whose destruction/recreation would cascade to the most",
        "downstream dependents. Treat these as high-care-on-apply.",
        "",
        f"  {'Resource':<48} {'Downstream':>10}  Flags",
    ]
    for r in rows:
        flags = []
        if r["is_crown_jewel"]:
            flags.append("crown")
        if r["internet_reachable"]:
            flags.append("inet")
        flag_s = ",".join(flags) if flags else "-"
        addr = r["resource"]
        if len(addr) > 48:
            addr = addr[:45] + "..."
        lines.append(f"  {addr:<48} {r['blast_radius']:>10}  {flag_s}")
    return "\n".join(lines) + "\n"


def render_blast_radius_html(top: Iterable[dict]) -> str:
    """HTML fragment for the report renderer. Empty input → "".

    Self-contained — no external CSS deps. Uses the same colour palette
    as the rest of the HTML report (warm tones for high-blast).
    """
    rows = list(top)
    if not rows:
        return ""
    body_rows = []
    for r in rows:
        flag_chips = []
        if r["is_crown_jewel"]:
            flag_chips.append('<span style="background:#fef3c7;color:#92400e;padding:1px 6px;border-radius:3px;font-size:11px">crown jewel</span>')
        if r["internet_reachable"]:
            flag_chips.append('<span style="background:#fee2e2;color:#991b1b;padding:1px 6px;border-radius:3px;font-size:11px">internet-reachable</span>')
        flags = " ".join(flag_chips) if flag_chips else ""
        # Heat scale on the radius cell — pale yellow ramps to red.
        radius = r["blast_radius"]
        # Cap intensity at a radius of 10 for the colour ramp so a single
        # mega-blast doesn't wash out everything else in the table.
        intensity = min(radius, 10) / 10
        bg_r = int(254 - (254 - 220) * intensity)
        bg_g = int(243 - (243 - 38) * intensity)
        bg_b = int(199 - (199 - 38) * intensity)
        body_rows.append(
            f'<tr>'
            f'<td><code>{r["resource"]}</code></td>'
            f'<td style="background:rgb({bg_r},{bg_g},{bg_b});color:#222;text-align:right;font-weight:600">{radius}</td>'
            f'<td>{flags}</td>'
            f'</tr>'
        )
    return (
        '<section style="margin-top:24px"><h2 style="color:#157878">Blast radius</h2>'
        '<p style="color:#555;font-size:14px">Resources whose destruction or '
        'recreation would cascade to the most downstream dependents. Treat as '
        'high-care-on-apply.</p>'
        '<table style="width:100%;border-collapse:collapse;font-size:14px">'
        '<thead><tr>'
        '<th style="text-align:left;padding:8px 6px;background:#157878;color:#fff">Resource</th>'
        '<th style="text-align:right;padding:8px 6px;background:#157878;color:#fff">Downstream</th>'
        '<th style="text-align:left;padding:8px 6px;background:#157878;color:#fff">Flags</th>'
        '</tr></thead><tbody>'
        + "".join(body_rows) +
        '</tbody></table></section>'
    )
