"""Tests for the registry_fingerprint detector + INFO-tier plumbing."""
from __future__ import annotations

import json
import subprocess
import sys

from helpers import DETECT_PY, FIXTURES_DIR, REPO_ROOT


def _run(target_dir: str, *extra: str) -> dict:
    """Run detect.py against a fixture, return parsed JSON output."""
    args = [
        sys.executable, str(DETECT_PY),
        "--target", str(FIXTURES_DIR / target_dir),
        "--format", "json",
        *extra,
    ]
    result = subprocess.run(args, capture_output=True, text=True, cwd=REPO_ROOT)
    return json.loads(result.stdout)


def test_aws_vpc_fingerprint_fires_on_positive_fixture() -> None:
    """The hand-rolled VPC fixture matches the AWS VPC fingerprint."""
    out = _run("mod_reuse_aws_vpc", "--show-info", "--only-fixture", "mod_reuse_aws_vpc")
    ids = [f["id"] for f in out["findings"]]
    assert "MOD-REUSE-AWS-VPC-001" in ids
    finding = next(f for f in out["findings"] if f["id"] == "MOD-REUSE-AWS-VPC-001")
    assert finding["urgency"] == "INFO"
    assert finding["confidence"] in ("low", "medium", "high")
    assert finding["registry_url"].startswith("https://registry.terraform.io/")


def test_aws_vpc_fingerprint_does_not_fire_on_clean_fixture() -> None:
    """A bare VPC + 2 subnets does not meet the supporting threshold."""
    out = _run("MOD-REUSE-AWS-VPC-001_clean", "--show-info")
    ids = [f["id"] for f in out["findings"]]
    assert "MOD-REUSE-AWS-VPC-001" not in ids


def test_gcp_network_fingerprint_fires_on_positive_fixture() -> None:
    out = _run("mod_reuse_gcp_network", "--show-info", "--only-fixture", "mod_reuse_gcp_network")
    ids = [f["id"] for f in out["findings"]]
    assert "MOD-REUSE-GCP-NETWORK-001" in ids


def test_azure_aks_fingerprint_fires_on_positive_fixture() -> None:
    out = _run("mod_reuse_azure_aks", "--show-info", "--only-fixture", "mod_reuse_azure_aks")
    ids = [f["id"] for f in out["findings"]]
    assert "MOD-REUSE-AZURE-AKS-001" in ids


def test_info_findings_hidden_without_show_info() -> None:
    """Default run filters INFO from findings list but keeps the count."""
    out = _run("mod_reuse_aws_vpc", "--only-fixture", "mod_reuse_aws_vpc")
    # Summary still tracks the count (advisory awareness)
    assert out["summary"]["counts"]["INFO"] == 1
    # But the rendered findings list is empty
    assert out["findings"] == []


def test_info_findings_visible_with_show_info() -> None:
    out = _run("mod_reuse_aws_vpc", "--show-info", "--only-fixture", "mod_reuse_aws_vpc")
    assert out["summary"]["counts"]["INFO"] == 1
    assert len(out["findings"]) == 1


def test_info_tier_does_not_move_risk_score() -> None:
    """INFO findings carry weight 0; positive fixture must score 100/A."""
    out = _run("mod_reuse_aws_vpc", "--show-info", "--only-fixture", "mod_reuse_aws_vpc")
    assert out["summary"]["score"] == 100
    assert out["summary"]["grade"] == "A"


def test_check_registry_fingerprint_supporting_threshold() -> None:
    """Below-threshold supporting-type count must not match."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from detect import _check_registry_fingerprint  # type: ignore

    fp = {
        "registry_module": "fake/module/aws",
        "registry_url": "https://example.com",
        "required": [{"type": "aws_vpc", "min": 1}],
        "supporting": {
            "threshold": 3,
            "types": ["aws_subnet", "aws_route_table", "aws_internet_gateway"],
        },
    }
    # Two supporting types — below threshold of 3.
    clusters = {
        "/dir": [
            {"type": "aws_vpc", "name": "a", "file": "/dir/main.tf", "line": 1},
            {"type": "aws_subnet", "name": "b", "file": "/dir/main.tf", "line": 5},
            {"type": "aws_route_table", "name": "c", "file": "/dir/main.tf", "line": 10},
        ],
    }
    assert _check_registry_fingerprint(fp, clusters) == []


def test_check_registry_fingerprint_exclusion_suppresses() -> None:
    """An exclusion type in the cluster suppresses the match."""
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from detect import _check_registry_fingerprint  # type: ignore

    fp = {
        "registry_module": "fake/module/aws",
        "registry_url": "https://example.com",
        "required": [{"type": "aws_vpc", "min": 1}],
        "supporting": {
            "threshold": 1,
            "types": ["aws_subnet"],
        },
        "exclusions": ["aws_vpc_ipam_pool"],
    }
    clusters = {
        "/dir": [
            {"type": "aws_vpc", "name": "a", "file": "/dir/main.tf", "line": 1},
            {"type": "aws_subnet", "name": "b", "file": "/dir/main.tf", "line": 5},
            {"type": "aws_vpc_ipam_pool", "name": "p", "file": "/dir/main.tf", "line": 10},
        ],
    }
    assert _check_registry_fingerprint(fp, clusters) == []
