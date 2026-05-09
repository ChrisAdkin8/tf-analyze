"""Drift-gate tests for the showcase demos under examples/.

These corpora are documentation surfaces — the README for each demo
states an exact finding count and graph shape that users see when
they open the dir in VS Code. A catalogue change that shifts those
numbers must update the demo READMEs in lock-step; the tests here
catch the drift locally instead of as a "wait, the demo doesn't
match the docs" surprise after publication.

Same pattern terragoat already uses (well, would if its drift gate
was in pytest rather than CI yaml) — assert exact counts, fail
loudly when they shift.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from helpers import DETECT_PY, REPO_ROOT


def _run(target_dir: Path, *extra: str) -> dict:
    args = [
        sys.executable, str(DETECT_PY),
        "--target", str(target_dir),
        "--format", "json",
        "--show-info",
        *extra,
    ]
    result = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    return json.loads(result.stdout)


# ---- examples/module-reuse-demo --------------------------------------------

class TestModuleReuseDemo:
    DIR = REPO_ROOT / "examples" / "module-reuse-demo"

    def test_exactly_five_module_reuse_findings(self) -> None:
        """README claims 5 — pinned. If you change the rule's threshold or
        the demo's resource counts, update the README too."""
        out = _run(self.DIR)
        ids = [f["id"] for f in out["findings"] if f["id"].startswith("MOD-REUSE-")]
        assert len(ids) == 5, f"expected 5 module-reuse findings, got {len(ids)}: {ids}"

    def test_admin_net_does_not_fire(self) -> None:
        """Below-threshold negative case — must stay silent."""
        out = _run(self.DIR)
        for f in out["findings"]:
            if f["id"].startswith("MOD-REUSE-"):
                assert "admin-net" not in f.get("file", ""), (
                    "admin-net/ fired the rule — supporting-types threshold logic regressed"
                )

    def test_shared_vpc_host_does_not_fire(self) -> None:
        """Excluded resource type negative case — must stay silent."""
        out = _run(self.DIR)
        for f in out["findings"]:
            if f["id"].startswith("MOD-REUSE-"):
                assert "shared-vpc-host" not in f.get("file", ""), (
                    "shared-vpc-host/ fired despite the exclusion — exclusion logic regressed"
                )

    def test_confidence_levels_span_all_three_tiers(self) -> None:
        """README pitches the demo as 'all three confidence colours visible'.
        Pin that property so reviewers can't accidentally remove it."""
        out = _run(self.DIR)
        confidences = {
            f.get("confidence")
            for f in out["findings"]
            if f["id"].startswith("MOD-REUSE-")
        }
        assert {"high", "medium", "low"} <= confidences, (
            f"expected high/medium/low all present, got {confidences}"
        )


# ---- examples/attack-graph-demo --------------------------------------------

class TestAttackGraphDemo:
    DIR = REPO_ROOT / "examples" / "attack-graph-demo"

    def test_graph_shape_matches_readme(self) -> None:
        """README states 19 nodes, 13 edges, 6 internet-reachable, 3 crown
        jewels. Pin those exactly — the README is screenshotted; any drift
        is a doc-update obligation, not a silent change."""
        out = _run(self.DIR, "--attack-graph")
        g = out.get("graph", {})
        nodes = g.get("nodes", [])
        edges = g.get("edges", [])

        n_nodes = len(nodes)
        n_edges = len(edges)
        n_internet = sum(1 for n in nodes if n.get("internet_reachable"))
        n_crown = sum(1 for n in nodes if n.get("is_crown_jewel"))

        assert n_nodes == 19, f"node count drifted: {n_nodes}"
        assert n_edges == 13, f"edge count drifted: {n_edges}"
        assert n_internet == 6, f"internet-reachable count drifted: {n_internet}"
        assert n_crown == 3, f"crown-jewel count drifted: {n_crown}"

    def test_internet_node_present(self) -> None:
        out = _run(self.DIR, "--attack-graph")
        node_ids = {n["id"] for n in out.get("graph", {}).get("nodes", [])}
        assert "INTERNET" in node_ids

    def test_three_crown_jewels_match_readme(self) -> None:
        out = _run(self.DIR, "--attack-graph")
        jewels = {
            n["id"] for n in out.get("graph", {}).get("nodes", [])
            if n.get("is_crown_jewel")
        }
        assert jewels == {
            "aws_s3_bucket.appdata",
            "aws_secretsmanager_secret.db_password",
            "aws_db_instance.appdb",
        }, f"crown jewels drifted from README list: {jewels}"
