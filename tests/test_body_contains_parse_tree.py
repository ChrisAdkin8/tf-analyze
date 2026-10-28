"""Rules that used to regex the raw resource body (`resource_body_contains`)
now read the argument they are about (`resource_arg`, `resource_has_block`
…), so a bad value set through a variable or local is caught, and a
lookalike in a string, a tag map or another block no longer fires.

Each case runs end to end (`detect.py --format json`) on the parse tree and
on the text fallback.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_forced_fallback(monkeypatch):
    # Each test picks its path through `path_mode`; the forced-fallback CI
    # job must not turn the tree half into a second fallback run.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


@pytest.fixture(params=["tree", "fallback"])
def path_mode(request):
    return request.param


def _findings(tmp_path: Path, text: str, mode: str) -> list[dict]:
    (tmp_path / "main.tf").write_text(text)
    env = dict(os.environ)
    if mode == "fallback":
        env["TF_ANALYZE_TEST_FORCE_FALLBACK"] = "1"
    out = subprocess.run(
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
        env=env,
    )
    return json.loads(out.stdout)["findings"]


def _fires(tmp_path: Path, text: str, rule: str, mode: str) -> bool:
    return any(f["id"] == rule for f in _findings(tmp_path, text, mode))


# ---- a bad value set through a variable or local is caught -----------------

VIA_VARIABLE = [
    (
        "SEC-GCP-SQL-PUBLIC-001",
        """
variable "public_ip" {
  default = true
}
resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = var.public_ip
    }
  }
}
""",
    ),
    (
        "SEC-K8S-HELM-003",
        """
variable "verify_chart" {
  default = false
}
resource "helm_release" "app" {
  name    = "app"
  chart   = "app"
  version = "1.2.3"
  verify  = var.verify_chart
}
""",
    ),
    (
        "STK-AZURE-AKS-AUTOSCALE-001",
        """
locals {
  autoscale = false
}
resource "azurerm_kubernetes_cluster" "k" {
  name                = "k"
  location            = "eastus"
  resource_group_name = "rg"
  dns_prefix          = "k"
  default_node_pool {
    name                = "default"
    vm_size             = "Standard_D2s_v3"
    enable_auto_scaling = local.autoscale
  }
}
""",
    ),
    (
        "SEC-GCP-STORAGE-IAM-001",
        """
variable "reader" {
  default = "allUsers"
}
resource "google_storage_bucket_iam_member" "m" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = var.reader
}
""",
    ),
    (
        "STK-K8S-PSA-002",
        """
locals {
  psa_labels = {
    "pod-security.kubernetes.io/enforce" = "privileged"
  }
}
resource "kubernetes_namespace" "ns" {
  metadata {
    name   = "apps"
    labels = local.psa_labels
  }
}
""",
    ),
    (
        "SEC-AWS-CLOUDFRONT-001",
        """
variable "viewer_policy" {
  default = "allow-all"
}
resource "aws_cloudfront_distribution" "d" {
  enabled = true
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    viewer_protocol_policy = var.viewer_policy
  }
}
""",
    ),
]


@pytest.mark.parametrize("rule, text", VIA_VARIABLE, ids=[r for r, _ in VIA_VARIABLE])
def test_bad_value_through_a_variable_is_caught(
    tmp_path, path_mode, rule, text
) -> None:
    assert _fires(tmp_path, text, rule, path_mode)


# ---- a lookalike elsewhere in the resource no longer fires ------------------

LOOKALIKES = [
    # The text is in a description string, not the exclusion filter.
    (
        "SEC-GCP-LOG-EXCLUSION-001",
        """
resource "google_logging_project_exclusion" "noise" {
  name        = "healthchecks"
  description = "Never add logs/cloudaudit.googleapis.com here"
  filter      = "resource.type = \\"http_load_balancer\\" AND httpRequest.status = 200"
}
""",
    ),
    # A tag that looks like a runtime setting; the real stack is current.
    (
        "STK-AZURE-WEBAPP-RUNTIME-001",
        """
resource "azurerm_linux_web_app" "w" {
  name                = "w"
  resource_group_name = "rg"
  location            = "eastus"
  service_plan_id     = "plan"
  tags = {
    node_version = "16"
  }
  site_config {
    application_stack {
      node_version = "20-lts"
    }
  }
}
""",
    ),
    # An annotation is not the label Pod Security Admission reads, and a
    # commented-out label does not count.
    (
        "STK-K8S-PSA-002",
        """
resource "kubernetes_namespace" "ns" {
  metadata {
    name = "apps"
    annotations = {
      "pod-security.kubernetes.io/enforce" = "privileged"
    }
    labels = {
      # "pod-security.kubernetes.io/enforce" = "privileged"
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}
""",
    ),
    # The policy has a rate-based rule; the default allow rule is normal.
    (
        "STK-GCP-CLOUDARMOR-001",
        """
resource "google_compute_security_policy" "p" {
  name = "edge"
  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}
""",
    ),
]


@pytest.mark.parametrize("rule, text", LOOKALIKES, ids=[r for r, _ in LOOKALIKES])
def test_lookalike_does_not_fire(tmp_path, path_mode, rule, text) -> None:
    assert not _fires(tmp_path, text, rule, path_mode)


# ---- old regexes that missed the provider's real values ---------------------

FIXED_VALUES = [
    # Linux function apps write .NET versions without the `v` prefix.
    (
        "STK-AZURE-FUNCTION-001",
        """
resource "azurerm_linux_function_app" "f" {
  name            = "f"
  service_plan_id = "plan"
  site_config {
    application_stack {
      dotnet_version = "3.1"
    }
  }
}
""",
    ),
    # Linux web apps write Node versions as `16-lts`.
    (
        "STK-AZURE-WEBAPP-RUNTIME-001",
        """
resource "azurerm_linux_web_app" "w" {
  name            = "w"
  service_plan_id = "plan"
  site_config {
    application_stack {
      node_version = "16-lts"
    }
  }
}
""",
    ),
    # Pre-v5 provider form of Google-managed replication.
    (
        "SEC-GCP-SECRET-002",
        """
resource "google_secret_manager_secret" "s" {
  secret_id = "s"
  replication {
    automatic = true
  }
}
""",
    ),
]


@pytest.mark.parametrize(
    "rule, text",
    FIXED_VALUES,
    ids=[f"{r}-{i}" for i, (r, _) in enumerate(FIXED_VALUES)],
)
def test_provider_values_the_old_regex_missed(tmp_path, path_mode, rule, text) -> None:
    assert _fires(tmp_path, text, rule, path_mode)


# ---- resource_has_block -----------------------------------------------------

NETPOL = """
resource "kubernetes_network_policy" "np" {
  metadata {
    name = "np"
  }
  spec {
    pod_selector {}
    policy_types = ["Egress"]
    egress {
      %s
    }
  }
}
"""


def test_has_block_empty(tmp_path, path_mode) -> None:
    rule = "SEC-K8S-NETPOL-002"
    assert _fires(tmp_path, NETPOL % "", rule, path_mode)
    # A comment is not content.
    assert _fires(tmp_path, NETPOL % "# allow nothing?", rule, path_mode)
    assert not _fires(
        tmp_path, NETPOL % "ports {\n        port = 53\n      }", rule, path_mode
    )


def test_has_block_present(tmp_path, path_mode) -> None:
    rule = "SEC-GCP-COMPUTE-PUBLIC-IP-001"
    base = """
resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-small"
  network_interface {
    network = "default"
    %s
  }
}
"""
    assert _fires(tmp_path, base % "access_config {}", rule, path_mode)
    assert _fires(
        tmp_path,
        base
        % 'dynamic "access_config" {\n      for_each = [1]\n      content {}\n    }',
        rule,
        path_mode,
    )
    assert not _fires(
        tmp_path,
        base % 'ipv6_access_config {\n      network_tier = "PREMIUM"\n    }',
        rule,
        path_mode,
    )
    assert not _fires(tmp_path, base % "", rule, path_mode)


def test_secret_auto_replication_with_cmek_is_fine(tmp_path, path_mode) -> None:
    text = """
resource "google_secret_manager_secret" "s" {
  secret_id = "s"
  replication {
    auto {
      customer_managed_encryption {
        kms_key_name = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
      }
    }
  }
}
"""
    assert not _fires(tmp_path, text, "SEC-GCP-SECRET-002", path_mode)
