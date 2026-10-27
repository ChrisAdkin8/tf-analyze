"""Rule accuracy fixes from the critical review: version lists that were
engine-blind or stale, name and block matches that were too loose, cost
patterns that could never fire, and duplicate rule pairs. Version
cut-offs were checked against the providers' docs on 2026-10-26."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _fired(tmp_path: Path, hcl: str, rule: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
            "--show-info",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {
        f.get("resource", "")
        for f in json.loads(proc.stdout)["findings"]
        if f["id"] == rule
    }


def _rds(name: str, engine: str, version: str) -> str:
    return (
        f'resource "aws_db_instance" "{name}" {{\n  engine         = "{engine}"\n'
        f'  engine_version = "{version}"\n}}\n'
    )


def test_rds_eol_versions_are_engine_aware(tmp_path) -> None:
    hcl = (
        _rds("pg13", "postgres", "13.12")
        + _rds("pg14", "postgres", "14.11")
        + _rds("my57", "mysql", "5.7.44")
        + _rds("my80", "mysql", "8.0.36")
        + _rds("my84", "mysql", "8.4.3")
        + _rds("maria105", "mariadb", "10.5.25")
        + _rds("maria1011", "mariadb", "10.11.8")
    )
    assert _fired(tmp_path, hcl, "STK-AWS-RDS-004") == {
        "aws_db_instance.pg13",
        "aws_db_instance.my57",
        "aws_db_instance.my80",
        "aws_db_instance.maria105",
    }


@pytest.mark.parametrize(
    ("runtime", "eol"),
    [
        ("python3.8", True),
        ("python3.9", True),
        ("nodejs16.x", True),
        ("nodejs20.x", True),
        ("provided.al2", True),
        ("python3.12", False),
        ("nodejs22.x", False),
        ("java21", False),
    ],
)
def test_lambda_deprecated_runtimes(tmp_path, runtime: str, eol: bool) -> None:
    hcl = f'resource "aws_lambda_function" "f" {{\n  function_name = "f"\n  runtime = "{runtime}"\n}}\n'
    assert bool(_fired(tmp_path, hcl, "STK-AWS-LAMBDA-001")) is eol


def test_kubernetes_versions_past_standard_support_and_one_rule_per_cloud(
    tmp_path,
) -> None:
    hcl = (
        'resource "aws_eks_cluster" "old" {\n  version = "1.33"\n}\n'
        'resource "aws_eks_cluster" "new" {\n  version = "1.34"\n}\n'
        'resource "google_container_cluster" "old" {\n  min_master_version = "1.33.4-gke.100"\n}\n'
        'resource "azurerm_kubernetes_cluster" "old" {\n  kubernetes_version = "1.33.2"\n}\n'
        'resource "azurerm_kubernetes_cluster" "new" {\n  kubernetes_version = "1.35.4"\n}\n'
    )
    assert _fired(tmp_path, hcl, "STK-K8S-VERSION-001") == {
        "aws_eks_cluster.old",
        "google_container_cluster.old",
    }
    assert _fired(tmp_path, hcl, "STK-AZURE-AKS-VERSION-001") == {
        "azurerm_kubernetes_cluster.old"
    }


def test_log_bucket_names_match_whole_parts_only(tmp_path) -> None:
    hcl = (
        'resource "aws_s3_bucket" "product_catalog" {\n  bucket = "acme-catalog"\n}\n'
        'resource "aws_s3_bucket" "access_logs" {\n  bucket = "acme-access-logs"\n}\n'
    )
    assert _fired(tmp_path, hcl, "SEC-AWS-LOG-RETENTION-001") == {
        "aws_s3_bucket.access_logs"
    }


def test_ipv6_access_config_is_not_a_public_ipv4(tmp_path) -> None:
    hcl = (
        'resource "google_compute_instance" "v6" {\n  name = "a"\n  network_interface {\n'
        '    network = "default"\n    ipv6_access_config {\n      network_tier = "PREMIUM"\n    }\n  }\n}\n'
        'resource "google_compute_instance" "v4" {\n  name = "b"\n  network_interface {\n'
        '    network = "default"\n    access_config {}\n  }\n}\n'
    )
    assert _fired(tmp_path, hcl, "SEC-GCP-COMPUTE-PUBLIC-IP-001") == {
        "google_compute_instance.v4"
    }


def test_aks_autoscaling_under_either_provider_name(tmp_path) -> None:
    hcl = (
        'resource "azurerm_kubernetes_cluster_node_pool" "v4_off" {\n  auto_scaling_enabled = false\n}\n'
        'resource "azurerm_kubernetes_cluster_node_pool" "v3_on" {\n  enable_auto_scaling = true\n}\n'
        'resource "azurerm_kubernetes_cluster_node_pool" "v4_on" {\n  auto_scaling_enabled = true\n}\n'
        'resource "azurerm_kubernetes_cluster_node_pool" "unset" {\n  name = "x"\n}\n'
    )
    # Turned off, under the azurerm 4+ name (only `enable_auto_scaling` was read).
    assert _fired(tmp_path, hcl, "STK-AZURE-AKS-AUTOSCALE-001") == {
        "azurerm_kubernetes_cluster_node_pool.v4_off",
    }
    # Not set at all; the azurerm 3 name set to true counts as set.
    assert _fired(tmp_path, hcl, "COST-AZURE-RISK-001") == {
        "azurerm_kubernetes_cluster_node_pool.unset",
    }


def test_public_gcs_binding_is_reported_once(tmp_path) -> None:
    hcl = (
        'resource "google_storage_bucket_iam_member" "pub" {\n  bucket = "b"\n'
        '  role   = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n'
        'resource "google_project_iam_member" "pub" {\n  project = "p"\n'
        '  role    = "roles/viewer"\n  member  = "allUsers"\n}\n'
    )
    assert _fired(tmp_path, hcl, "SEC-GCP-STORAGE-IAM-001") == {
        "google_storage_bucket_iam_member.pub"
    }
    assert _fired(tmp_path, hcl, "SEC-GCP-IAM-002") == {"google_project_iam_member.pub"}


def test_aks_public_api_rules_no_longer_duplicate(tmp_path) -> None:
    hcl = (
        'resource "azurerm_kubernetes_cluster" "open" {\n  name = "a"\n}\n'
        'resource "azurerm_kubernetes_cluster" "allowlisted" {\n  name = "b"\n'
        '  api_server_access_profile {\n    authorized_ip_ranges = ["203.0.113.0/24"]\n  }\n}\n'
        'resource "azurerm_kubernetes_cluster" "private" {\n  name = "c"\n'
        "  private_cluster_enabled = true\n}\n"
    )
    assert _fired(tmp_path, hcl, "SEC-AZURE-AKS-PRIVATE-001") == {
        "azurerm_kubernetes_cluster.open",
        "azurerm_kubernetes_cluster.allowlisted",
    }
    assert _fired(tmp_path, hcl, "STK-AZURE-AKS-004") == {
        "azurerm_kubernetes_cluster.open"
    }
