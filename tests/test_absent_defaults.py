"""Leaving a setting out counts when the provider's default is the unsafe one.

Defaults checked in the provider source:
  * azurerm `azurerm_cosmosdb_account.public_network_access_enabled`:
    Optional, Default true.
  * google `google_sql_database_instance.settings.ip_configuration.ipv4_enabled`:
    Optional, Default true (a public IPv4 address).
  * GCE: without `block-project-ssh-keys` in instance metadata, project-wide
    SSH keys work on the instance.
Also: `bind` / `escalate` / `impersonate` were only checked on Roles, not
ClusterRoles. `helm_release.verify` stays explicit-only on purpose.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"


def _ids(tmp_path: Path, hcl: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


COSMOS = (
    'resource "azurerm_cosmosdb_account" "c" {\n  name = "c"\n  offer_type = "Standard"\n%s'
    '  consistency_policy {\n    consistency_level = "Session"\n  }\n'
    '  geo_location {\n    location = "westeurope"\n    failover_priority = 0\n  }\n}\n'
)
SQL = (
    'resource "google_sql_database_instance" "db" {\n  database_version = "POSTGRES_15"\n'
    '  settings {\n    tier = "db-f1-micro"\n%s  }\n}\n'
)
VM = (
    'resource "google_compute_instance" "vm" {\n  name = "vm"\n  machine_type = "e2-small"\n%s'
    '  boot_disk {\n    initialize_params {\n      image = "debian-cloud/debian-12"\n    }\n  }\n'
    '  network_interface {\n    network = "default"\n  }\n}\n'
)


@pytest.mark.parametrize(
    ("setting", "fires"),
    [
        ("", True),
        ("  public_network_access_enabled = true\n", True),
        ("  public_network_access_enabled = false\n", False),
    ],
)
def test_cosmos_public_access_default_is_public(tmp_path, setting, fires) -> None:
    assert ("SEC-AZURE-COSMOS-001" in _ids(tmp_path, COSMOS % setting)) is fires


@pytest.mark.parametrize(
    ("ip_config", "fires"),
    [
        ("", True),
        (
            '    ip_configuration {\n      private_network = "projects/p/global/networks/n"\n    }\n',
            True,
        ),
        (
            '    ip_configuration {\n      ipv4_enabled    = false\n      private_network = "projects/p/global/networks/n"\n    }\n',
            False,
        ),
    ],
)
def test_cloud_sql_public_ip_default_is_public(tmp_path, ip_config, fires) -> None:
    assert ("SEC-GCP-SQL-PUBLIC-001" in _ids(tmp_path, SQL % ip_config)) is fires


@pytest.mark.parametrize(
    ("metadata", "fires"),
    [
        ("", True),
        ('  metadata = {\n    enable-oslogin = "TRUE"\n  }\n', True),
        ('  metadata = {\n    block-project-ssh-keys = "FALSE"\n  }\n', True),
        ('  metadata = {\n    block-project-ssh-keys = "TRUE"\n  }\n', False),
    ],
)
def test_project_ssh_keys_are_allowed_unless_blocked(tmp_path, metadata, fires) -> None:
    assert ("SEC-GCP-COMPUTE-PROJSSH-001" in _ids(tmp_path, VM % metadata)) is fires


@pytest.mark.parametrize("verb", ["bind", "escalate", "impersonate"])
def test_escalation_verbs_on_a_cluster_role(tmp_path, verb) -> None:
    hcl = (
        'resource "kubernetes_cluster_role" "r" {\n  metadata {\n    name = "r"\n  }\n'
        f'  rule {{\n    api_groups = ["rbac.authorization.k8s.io"]\n    resources  = ["clusterroles"]\n'
        f'    verbs      = ["get", "{verb}"]\n  }}\n}}\n'
    )
    assert "SEC-K8S-RBAC-001" in _ids(tmp_path, hcl)


def test_helm_verify_is_explicit_only(tmp_path) -> None:
    hcl = 'resource "helm_release" "h" {\n  name = "h"\n  chart = "nginx"\n  repository = "https://charts.example.com"\n  version = "1.2.3"\n}\n'
    assert "SEC-K8S-HELM-003" not in _ids(tmp_path, hcl)
    assert "SEC-K8S-HELM-003" in _ids(
        tmp_path,
        hcl.replace('version = "1.2.3"', 'version = "1.2.3"\n  verify = false'),
    )
