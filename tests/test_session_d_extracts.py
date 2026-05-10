"""Tests for the Session-D modularisation extract: `_attack_graph.py`.

The functional contracts for the attack-graph build + render are
already covered by `tests/test_attack_graph.py`, which reaches them
via the `detect` module's re-export shim. These tests cover the
*seam contract* — that `_attack_graph.py` exposes the names callers
expect, and that `detect.py` re-exports each name as a binding
(not a copy) so future renames stay in sync.

Same shape as the prior session extracts in
`tests/test_session_a_extracts.py`, `tests/test_session_b_extracts.py`,
and `tests/test_session_c_extracts.py`.
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestAttackGraphModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _attack_graph
        # Constants
        assert hasattr(_attack_graph, "_CROWN_JEWEL_TYPES")
        assert hasattr(_attack_graph, "_NODE_TYPE_MAP")
        # 10 internet-reachability regexes (9 _INET_* + 1 Azure)
        for n in (
            "_INET_EC2_PUBLIC_IP_RE", "_INET_RDS_PUBLIC_RE",
            "_INET_SQL_PUBLIC_IP_RE", "_INET_SG_CIDR_RE",
            "_INET_SG_IPV6_RE", "_INET_CLOUDRUN_ALL_RE",
            "_INET_ALB_FACING_RE", "_INET_GCE_ACCESS_CFG_RE",
            "_INET_GKE_PRIVATE_RE", "_INET_AZ_IP_RESTRICTION_RE",
        ):
            assert hasattr(_attack_graph, n), n
        # 15 edge-inference regexes
        for n in (
            "_EDGE_IAM_PROFILE_RE", "_EDGE_PROFILE_ROLE_RE",
            "_EDGE_KMS_KEY_ID_RE", "_EDGE_KMS_KEY_NAME_RE",
            "_EDGE_KMS_MASTER_RE", "_EDGE_SECRET_ARN_RE",
            "_EDGE_SG_REF_RE", "_EDGE_GCP_SA_RE",
            "_EDGE_GCS_BUCKET_RE", "_EDGE_AZ_MI_RE",
            "_EDGE_AZ_KV_RE", "_EDGE_AZ_STORAGE_RE",
            "_EDGE_AZ_SQL_RE", "_EDGE_GCP_SA_EMAIL_RE",
            "_EDGE_GCP_SA_NAME_RE",
        ):
            assert hasattr(_attack_graph, n), n
        # 7 functions
        for n in (
            "_is_internet_reachable", "build_attack_graph",
            "_score_fix_centrality", "_apply_reachability_urgency",
            "_mermaid_id", "graph_to_mermaid", "_render_graph_html",
        ):
            assert hasattr(_attack_graph, n), n

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        """Every legacy `detect.<name>` symbol must be the same object
        as the one in `_attack_graph.py`. Existing tests in
        `test_attack_graph.py` reach `detect.build_attack_graph`,
        `detect.graph_to_mermaid`, and `detect._render_graph_html`
        through this shim; if it ever decays into a copy this catches
        it."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _attack_graph
        # Sample across the surface — the names listed in
        # test_module_imports_cleanly cover the full set, but binding
        # identity is what we lock here. 34 names total; spot-check the
        # functions (compiled regexes have stable `is`-identity through
        # re-import).
        for n in (
            "_CROWN_JEWEL_TYPES", "_NODE_TYPE_MAP",
            "_INET_EC2_PUBLIC_IP_RE", "_INET_AZ_IP_RESTRICTION_RE",
            "_EDGE_IAM_PROFILE_RE", "_EDGE_GCP_SA_NAME_RE",
            "_is_internet_reachable", "build_attack_graph",
            "_score_fix_centrality", "_apply_reachability_urgency",
            "_mermaid_id", "graph_to_mermaid", "_render_graph_html",
        ):
            assert getattr(detect, n) is getattr(_attack_graph, n), (
                f"{n}: detect.{n} is NOT the same object as "
                f"_attack_graph.{n} — re-export shim decayed into a copy"
            )

    def test_urgency_tiers_lives_in_scoring(self) -> None:
        """Session D moved `_URGENCY_TIERS` from detect.py into
        `_scoring.py` so `_attack_graph._apply_reachability_urgency`
        could import it cross-seam. Confirm the binding chain:
        `_attack_graph._URGENCY_TIERS` is `_scoring._URGENCY_TIERS` is
        `detect._URGENCY_TIERS`."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _scoring
        import _attack_graph
        assert _scoring._URGENCY_TIERS == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert detect._URGENCY_TIERS is _scoring._URGENCY_TIERS
        # _attack_graph imports it under the same name at module load
        assert _attack_graph._URGENCY_TIERS is _scoring._URGENCY_TIERS

    def test_round_trip_through_shim(self) -> None:
        """End-to-end: build a graph on a hand-rolled resource index
        with one internet-facing SG → crown-jewel DB path, then render
        through both Mermaid and HTML. Without this, a regression in
        either the import order or in `_apply_reachability_urgency`'s
        cross-seam `_URGENCY_TIERS` lookup would only surface during a
        real workspace scan."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        resource_index = {
            "aws_security_group.web_sg": {
                "type": "aws_security_group",
                "file": "main.tf", "line": 1,
                "body": 'cidr_blocks = ["0.0.0.0/0"]',
                "name": "web_sg",
            },
            "aws_db_instance.crown": {
                "type": "aws_db_instance",
                "file": "main.tf", "line": 10,
                "body": "vpc_security_group_ids = [aws_security_group.web_sg.id]",
                "name": "crown",
            },
        }
        graph = detect.build_attack_graph(resource_index, [])
        node_ids = {n["id"] for n in graph["nodes"]}
        assert "INTERNET" in node_ids
        assert "aws_db_instance.crown" in node_ids
        assert "aws_security_group.web_sg" in node_ids
        # SG with 0.0.0.0/0 should be internet-reachable; reachability
        # should propagate to its dependent DB via the security_group
        # edge label that build_attack_graph adds.
        sg = next(n for n in graph["nodes"] if n["id"] == "aws_security_group.web_sg")
        assert sg["internet_reachable"] is True
        # DB is a crown jewel
        db = next(n for n in graph["nodes"] if n["id"] == "aws_db_instance.crown")
        assert db["is_crown_jewel"] is True

        # Mermaid render must be a fenced flowchart
        mermaid = detect.graph_to_mermaid(graph)
        assert mermaid.startswith("```mermaid")
        assert "flowchart LR" in mermaid
        assert mermaid.endswith("```")

        # HTML render must be self-contained (no external <script src=...>)
        html = detect._render_graph_html(graph)
        assert "<svg" in html and 'id="ag-svg"' in html
        assert "<script>" in html and "src=" not in html

    def test_apply_reachability_urgency_promotes_and_demotes(self) -> None:
        """Lock the promote/demote rules of
        `_apply_reachability_urgency` at the seam — these drive the
        score-bump for critical-path findings and the demotion for
        findings on unreachable resources. Critical contract for the
        attack-graph value-add."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _attack_graph import _apply_reachability_urgency
        graph = {
            "nodes": [
                {"id": "aws_db_instance.crown", "internet_reachable": True},
                {"id": "aws_lambda_function.unreachable", "internet_reachable": False},
            ],
            "critical_path": ["aws_db_instance.crown"],
        }
        findings = [
            {"id": "SEC-001", "resource": "aws_db_instance.crown"},
            {"id": "SEC-002", "resource": "aws_lambda_function.unreachable"},
        ]
        entry_map = {
            "SEC-001": {"default_urgency": "MEDIUM"},
            "SEC-002": {"default_urgency": "MEDIUM"},
        }
        _apply_reachability_urgency(findings, graph, entry_map)
        # On critical path → MEDIUM bumped to HIGH; flag set
        assert findings[0]["urgency"] == "HIGH"
        assert findings[0]["on_critical_path"] is True
        # Off the internet graph entirely → MEDIUM demoted to LOW
        assert findings[1]["urgency"] == "LOW"
