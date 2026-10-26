"""Azure, GCP and Kubernetes rules fire on the insecure shape and stay
quiet on the secure one (critical review, batch 3)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _catalog

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


def test_sql_server_needs_an_entra_admin_block(tmp_path) -> None:
    hcl = """
resource "azurerm_mssql_server" "sql_only" {
  name    = "a"
  version = "12.0"
}
resource "azurerm_mssql_server" "entra" {
  name    = "b"
  version = "12.0"
  azuread_administrator {
    login_username = "sql-admins"
    object_id      = "00000000-0000-0000-0000-000000000000"
  }
}
"""
    assert _fired(tmp_path, hcl, "SEC-AZURE-SQL-001") == {
        "azurerm_mssql_server.sql_only"
    }


def test_sql_tde_only_when_explicitly_off(tmp_path) -> None:
    hcl = """
resource "azurerm_mssql_database" "default" {
  name      = "a"
  server_id = "s"
}
resource "azurerm_mssql_database" "off" {
  name                                = "b"
  server_id                           = "s"
  transparent_data_encryption_enabled = false
}
"""
    assert _fired(tmp_path, hcl, "STK-AZURE-SQL-TDE-001") == {
        "azurerm_mssql_database.off"
    }


def test_linux_vm_password_auth_only_when_turned_on(tmp_path) -> None:
    hcl = """
resource "azurerm_linux_virtual_machine" "default" {
  name = "a"
}
resource "azurerm_linux_virtual_machine" "password" {
  name                            = "b"
  disable_password_authentication = false
}
"""
    assert _fired(tmp_path, hcl, "SEC-AZURE-VM-001") == {
        "azurerm_linux_virtual_machine.password"
    }


def test_redis_and_storage_current_argument_names(tmp_path) -> None:
    hcl = """
resource "azurerm_redis_cache" "default" {
  name = "a"
}
resource "azurerm_redis_cache" "non_ssl" {
  name                 = "b"
  non_ssl_port_enabled = true
}
resource "azurerm_storage_account" "default" {
  name = "c"
}
resource "azurerm_storage_account" "http" {
  name                       = "d"
  https_traffic_only_enabled = false
}
"""
    assert _fired(tmp_path, hcl, "SEC-AZURE-REDIS-001") == {
        "azurerm_redis_cache.non_ssl"
    }
    assert _fired(tmp_path, hcl, "SEC-AZURE-STORAGE-001") == {
        "azurerm_storage_account.http"
    }


def test_kubernetes_secret_literal_values_only(tmp_path) -> None:
    hcl = """
resource "kubernetes_secret" "literal" {
  metadata { name = "a" }
  data = {
    password = "hunter2"
  }
}
resource "kubernetes_secret_v1" "from_var" {
  metadata { name = "b" }
  data = {
    password = var.db_password
    url      = "${var.host}:5432"
  }
}
resource "kubernetes_secret_v1" "block_literal" {
  metadata { name = "c" }
  data {
    token = "abc"
  }
}
"""
    assert _fired(tmp_path, hcl, "SEC-K8S-SECRET-001") == {
        "kubernetes_secret.literal",
        "kubernetes_secret_v1.block_literal",
    }


def test_kubernetes_rules_cover_v1_resources_and_attribute_order(tmp_path) -> None:
    hcl = """
resource "kubernetes_cluster_role_binding_v1" "admin" {
  metadata { name = "ops" }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }
  subject {
    name = "system:masters"
    kind = "Group"
  }
}
resource "kubernetes_cluster_role_binding" "named_like_admin" {
  metadata { name = "cluster-admin" }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "view"
  }
  subject {
    kind = "User"
    name = "alice"
  }
}
"""
    admin = {"kubernetes_cluster_role_binding_v1.admin"}
    assert _fired(tmp_path, hcl, "SEC-K8S-RBAC-001") == admin
    assert _fired(tmp_path, hcl, "SEC-K8S-RBAC-002") == admin


def test_network_policy_absence_accepts_either_api_version(tmp_path) -> None:
    namespace = (
        'resource "kubernetes_namespace_v1" "app" {\n  metadata { name = "app" }\n}\n'
    )
    assert _fired(tmp_path, namespace, "SEC-K8S-NETPOL-001")
    policy = 'resource "kubernetes_network_policy_v1" "deny" {\n  metadata { name = "deny" }\n}\n'
    assert not _fired(tmp_path, namespace + policy, "SEC-K8S-NETPOL-001")


def test_kubernetes_type_aliases() -> None:
    assert _catalog.kubernetes_type_aliases("kubernetes_secret") == (
        "kubernetes_secret",
        "kubernetes_secret_v1",
    )
    assert _catalog.kubernetes_type_aliases("kubernetes_secret_v1") == (
        "kubernetes_secret_v1",
        "kubernetes_secret",
    )
    assert _catalog.kubernetes_type_aliases("aws_s3_bucket") == ("aws_s3_bucket",)


def test_gke_settings_present_but_switched_off(tmp_path) -> None:
    hcl = """
resource "google_container_cluster" "bare" {
  name = "bare"
}
resource "google_container_cluster" "off" {
  name = "off"
  database_encryption {
    state    = "DECRYPTED"
    key_name = ""
  }
  binary_authorization {
    evaluation_mode = "DISABLED"
  }
  network_policy {
    enabled = false
  }
}
resource "google_container_cluster" "good" {
  name              = "good"
  datapath_provider = "ADVANCED_DATAPATH"
  database_encryption {
    state    = "ENCRYPTED"
    key_name = "k"
  }
  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }
}
"""
    bare, off = "google_container_cluster.bare", "google_container_cluster.off"
    assert _fired(tmp_path, hcl, "SEC-GCP-GKE-DBENC-001") == {bare}
    assert _fired(tmp_path, hcl, "STK-GCP-GKE-003") == {off}
    assert _fired(tmp_path, hcl, "SEC-GCP-GKE-BINAUTHZ-001") == {bare, off}
    assert _fired(tmp_path, hcl, "SEC-GCP-GKE-NETWORK-POLICY-001") == {bare, off}


def test_gcp_kms_rotation_only_for_encrypt_decrypt_keys(tmp_path) -> None:
    hcl = """
resource "google_kms_crypto_key" "symmetric" {
  name = "a"
}
resource "google_kms_crypto_key" "signing" {
  name    = "b"
  purpose = "ASYMMETRIC_SIGN"
}
"""
    assert _fired(tmp_path, hcl, "STK-GCP-KMS-001") == {
        "google_kms_crypto_key.symmetric"
    }


def test_kubernetes_secret_quoted_keys_do_not_hide_literals(tmp_path) -> None:
    hcl = """
resource "kubernetes_secret" "quoted_key" {
  metadata { name = "a" }
  data = {
    "password" = "hunter2"
  }
}
resource "kubernetes_secret_v1" "dockercfg" {
  metadata { name = "b" }
  data = {
    ".dockerconfigjson" = "{}"
  }
}
resource "kubernetes_secret_v1" "quoted_key_var" {
  metadata { name = "c" }
  data = {
    "password" = var.db_password
    "dsn"      = format("%s:5432", var.host)
  }
}
"""
    assert _fired(tmp_path, hcl, "SEC-K8S-SECRET-001") == {
        "kubernetes_secret.quoted_key", "kubernetes_secret_v1.dockercfg",
    }


def test_gcp_kms_unresolved_purpose_still_fires(tmp_path) -> None:
    hcl = """
variable "key_purpose" {
  type = string
}
resource "google_kms_crypto_key" "unresolved" {
  name    = "a"
  purpose = var.key_purpose
}
"""
    assert _fired(tmp_path, hcl, "STK-GCP-KMS-001") == {"google_kms_crypto_key.unresolved"}


def test_kubernetes_secret_regex_does_not_backtrack_exponentially() -> None:
    import re
    import time

    entry = next(
        e for e in _catalog.load_catalog(REPO / "catalog") if e["id"] == "SEC-K8S-SECRET-001"
    )
    # Many interpolated strings and no literal: the regex must fail fast.
    body = "  data = {\n    k = [" + ", ".join(['"${a}"'] * 60) + "]\n"
    for pattern in entry["patterns"]:
        start = time.perf_counter()
        re.search(pattern["regex"], body)
        assert time.perf_counter() - start < 0.5, pattern["regex"]
