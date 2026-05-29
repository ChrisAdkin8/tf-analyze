"""Unit tests for ``_blast_radius`` — graph traversal + JSON shape.

The module is pure-functional so tests build small synthetic graphs
directly rather than running the engine. End-to-end coverage (engine
emits the ``blast_radius`` block + per-finding annotation) lives in
``test_detect.py`` / ``test_public_scanner.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from helpers import REPO_ROOT

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _blast_radius import (  # type: ignore
    compute_blast_radius,
    annotate_findings_with_blast_radius,
    top_blast_radius_resources,
    render_blast_radius_text,
    render_blast_radius_html,
)


def _g(nodes: list, edges: list) -> dict:
    return {
        "nodes": [{"id": n, "type": "compute", "file": f"{n}.tf",
                   "line": 1, "is_crown_jewel": False,
                   "internet_reachable": False} for n in nodes],
        "edges": [{"from": a, "to": b, "label": "ref"} for a, b in edges],
        "critical_path": [],
        "internet_node_id": None,
    }


def test_linear_chain_counts_downstream() -> None:
    """a → b → c → d : a's blast is 3, b's is 2, c's is 1, d's is 0."""
    graph = _g(["a", "b", "c", "d"], [("a", "b"), ("b", "c"), ("c", "d")])
    blast = compute_blast_radius(graph)
    assert blast["a"] == 3
    assert blast["b"] == 2
    assert blast["c"] == 1
    assert blast["d"] == 0


def test_fan_out() -> None:
    """One root with three direct children — blast is 3."""
    graph = _g(["root", "x", "y", "z"], [("root", "x"), ("root", "y"), ("root", "z")])
    assert compute_blast_radius(graph)["root"] == 3


def test_diamond_shape_does_not_double_count() -> None:
    """a → b → d  and  a → c → d. ``a``'s blast is 3 (b, c, d), not 4."""
    graph = _g(
        ["a", "b", "c", "d"],
        [("a", "b"), ("a", "c"), ("b", "d"), ("c", "d")],
    )
    assert compute_blast_radius(graph)["a"] == 3


def test_cycle_terminates_and_counts_each_node_once() -> None:
    """a → b → c → a (cycle) plus a → d (acyclic branch).
    Each visit counted once; algo must not loop forever."""
    graph = _g(["a", "b", "c", "d"], [("a", "b"), ("b", "c"), ("c", "a"), ("a", "d")])
    blast = compute_blast_radius(graph)
    # `a`'s downstream is {b, c, d} — 3 (own ID excluded)
    assert blast["a"] == 3
    # b's downstream is {c, a, d}, also 3
    assert blast["b"] == 3


def test_isolated_node_blast_zero() -> None:
    graph = _g(["lonely"], [])
    assert compute_blast_radius(graph)["lonely"] == 0


def test_empty_graph() -> None:
    assert compute_blast_radius({"nodes": [], "edges": []}) == {}


def test_edge_pointing_at_unknown_node_ignored() -> None:
    """A dangling edge whose target isn't in nodes shouldn't blow up
    or inflate the count."""
    graph = _g(["a"], [])
    # Inject a stray edge.
    graph["edges"].append({"from": "a", "to": "missing", "label": "ref"})
    assert compute_blast_radius(graph)["a"] == 0


# ---------------------------------------------------------------------------
# annotate_findings_with_blast_radius
# ---------------------------------------------------------------------------


def test_annotate_findings_populates_zero_for_missing_resource() -> None:
    findings = [
        {"id": "X", "resource": "a"},
        {"id": "Y", "resource": "z-not-in-graph"},
        {"id": "Z", "resource": ""},  # workspace-wide finding
    ]
    annotate_findings_with_blast_radius(findings, {"a": 5, "b": 2})
    assert findings[0]["blast_radius"] == 5
    assert findings[1]["blast_radius"] == 0
    assert findings[2]["blast_radius"] == 0


# ---------------------------------------------------------------------------
# top_blast_radius_resources
# ---------------------------------------------------------------------------


def test_top_n_excludes_synthetic_internet_node() -> None:
    graph = _g(["INTERNET", "a"], [("INTERNET", "a")])
    blast = compute_blast_radius(graph)
    top = top_blast_radius_resources(graph, blast)
    assert all(r["resource"] != "INTERNET" for r in top)


def test_top_n_excludes_zero_blast_leaves() -> None:
    graph = _g(["a", "b"], [("a", "b")])
    blast = compute_blast_radius(graph)
    top = top_blast_radius_resources(graph, blast)
    # `b` has blast 0; should not appear.
    assert {r["resource"] for r in top} == {"a"}


def test_top_n_respects_min_radius() -> None:
    graph = _g(["a", "b", "c"], [("a", "b"), ("a", "c")])
    blast = compute_blast_radius(graph)
    # min_radius=3 excludes `a` (blast 2)
    assert top_blast_radius_resources(graph, blast, min_radius=3) == []


def test_top_n_caps_results() -> None:
    """Many high-blast nodes → only top_n returned."""
    edges = [("root", f"leaf{i}") for i in range(20)]
    graph = _g(["root"] + [f"leaf{i}" for i in range(20)], edges)
    blast = compute_blast_radius(graph)
    assert len(top_blast_radius_resources(graph, blast, top_n=5)) == 1  # only root has non-zero
    # Make multiple roots — top_n caps the list.
    multi = _g([f"r{i}" for i in range(15)] + ["leaf"],
               [(f"r{i}", "leaf") for i in range(15)])
    multi_blast = compute_blast_radius(multi)
    assert len(top_blast_radius_resources(multi, multi_blast, top_n=5)) == 5


def test_top_n_deterministic_tie_break() -> None:
    """Two nodes with identical blast — alpha order on id breaks the tie."""
    graph = _g(["zebra", "apple", "leaf"], [("zebra", "leaf"), ("apple", "leaf")])
    blast = compute_blast_radius(graph)
    top = top_blast_radius_resources(graph, blast)
    # Both have blast 1; apple should appear before zebra.
    assert [r["resource"] for r in top] == ["apple", "zebra"]


# ---------------------------------------------------------------------------
# Renderers — smoke tests
# ---------------------------------------------------------------------------


def test_render_text_empty_returns_blank() -> None:
    assert render_blast_radius_text([]) == ""


def test_render_text_has_header_and_row() -> None:
    out = render_blast_radius_text([
        {"resource": "aws_vpc.main", "type": "network",
         "file": "vpc.tf", "line": 12, "blast_radius": 8,
         "is_crown_jewel": False, "internet_reachable": False},
    ])
    assert "Blast radius" in out
    assert "aws_vpc.main" in out
    assert "8" in out


def test_render_html_empty_returns_blank() -> None:
    assert render_blast_radius_html([]) == ""


def test_render_html_has_table_and_chips() -> None:
    out = render_blast_radius_html([
        {"resource": "aws_vpc.main", "type": "network",
         "file": "vpc.tf", "line": 12, "blast_radius": 8,
         "is_crown_jewel": True, "internet_reachable": True},
    ])
    assert "<table" in out
    assert "aws_vpc.main" in out
    assert "crown jewel" in out
    assert "internet-reachable" in out


def test_render_html_escapes_resource_name() -> None:
    # V2 — a crafted resource name (attacker-influenced via a scanned repo
    # in the public scanner / fleet reports) must not inject markup.
    out = render_blast_radius_html([
        {"resource": "<img src=x onerror=alert(1)>", "type": "n",
         "file": "f.tf", "line": 1, "blast_radius": 3,
         "is_crown_jewel": False, "internet_reachable": False},
    ])
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;img src=x onerror=alert(1)&gt;" in out
