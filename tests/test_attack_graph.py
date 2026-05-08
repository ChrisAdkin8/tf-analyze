"""Unit tests for build_attack_graph()."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import detect  # noqa: E402


def _resource(rtype: str, name: str, body: str = "") -> tuple[str, dict]:
    addr = f"{rtype}.{name}"
    return addr, {"type": rtype, "name": name, "body": body, "file": "main.tf", "line": 1}


class TestBuildAttackGraph:
    def test_graph_nodes_created(self):
        resources = dict([
            _resource("aws_instance", "web"),
            _resource("aws_s3_bucket", "data"),
        ])
        graph = detect.build_attack_graph(resources, [])
        node_ids = {n["id"] for n in graph["nodes"]}
        assert "aws_instance.web" in node_ids
        assert "aws_s3_bucket.data" in node_ids

    def test_graph_always_has_internet_node(self):
        graph = detect.build_attack_graph({}, [])
        node_ids = {n["id"] for n in graph["nodes"]}
        assert "INTERNET" in node_ids

    def test_graph_iam_role_edge(self):
        # _EDGE_PROFILE_ROLE_RE matches `role = aws_iam_role.<name>.`
        body = "  role = aws_iam_role.worker.arn\n"
        resources = dict([
            _resource("aws_instance", "web", body),
            _resource("aws_iam_role", "worker"),
        ])
        graph = detect.build_attack_graph(resources, [])
        edges = {(e["from"], e["to"]) for e in graph["edges"]}
        assert ("aws_instance.web", "aws_iam_role.worker") in edges

    def test_graph_crown_jewel_s3_bucket(self):
        resources = dict([_resource("aws_s3_bucket", "data")])
        graph = detect.build_attack_graph(resources, [])
        nodes = {n["id"]: n for n in graph["nodes"]}
        assert nodes["aws_s3_bucket.data"]["is_crown_jewel"] is True

    def test_graph_crown_jewel_db_instance(self):
        resources = dict([_resource("aws_db_instance", "db")])
        graph = detect.build_attack_graph(resources, [])
        nodes = {n["id"]: n for n in graph["nodes"]}
        assert nodes["aws_db_instance.db"]["is_crown_jewel"] is True

    def test_graph_internet_reachable_sg(self):
        body = '  ingress {\n    cidr_blocks = ["0.0.0.0/0"]\n    from_port = 80\n  }\n'
        resources = dict([_resource("aws_security_group", "public", body)])
        graph = detect.build_attack_graph(resources, [])
        nodes = {n["id"]: n for n in graph["nodes"]}
        assert nodes["aws_security_group.public"]["internet_reachable"] is True

    def test_graph_finding_attached_by_resource_key(self):
        resources = dict([_resource("aws_s3_bucket", "data")])
        # findings keyed by "resource" field (not resource_address)
        findings = [{"id": "SEC-AWS-S3-001", "file": "main.tf", "line": 1, "resource": "aws_s3_bucket.data"}]
        graph = detect.build_attack_graph(resources, findings)
        nodes = {n["id"]: n for n in graph["nodes"]}
        assert "SEC-AWS-S3-001" in nodes["aws_s3_bucket.data"]["findings"]

    def test_graph_edge_fields(self):
        body = "  role = aws_iam_role.r.arn\n"
        resources = dict([
            _resource("aws_instance", "web", body),
            _resource("aws_iam_role", "r"),
        ])
        graph = detect.build_attack_graph(resources, [])
        assert graph["edges"], "Expected at least one edge"
        edge = graph["edges"][0]
        assert "from" in edge
        assert "to" in edge
        assert "label" in edge
