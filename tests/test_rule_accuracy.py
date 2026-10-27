"""Rules that gave the wrong answer (critical review, 2026-10-27).

Each case pins both directions: the insecure shape fires, and the
secure (or differently-written but equivalent) shape does not.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECT = REPO / "scripts" / "detect.py"


def _ids(target: Path, *extra: str) -> list[tuple[str, str]]:
    """(rule id, resource) for every finding in a JSON scan of `target`."""
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--format",
            "json",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return [
        (f["id"], f.get("resource", "")) for f in json.loads(proc.stdout)["findings"]
    ]


def _write(dest: Path, text: str) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "main.tf").write_text(text)
    return dest


# ---- "the whole internet", however it is written ----------------------------

SG_V6 = """\
resource "aws_security_group" "sg" {
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["%s"]
  }
}
"""


@pytest.mark.parametrize("cidr", ["::/0", "0::/0", "::0/0", "0000:0000::/0"])
def test_every_spelling_of_ipv6_any_is_world_open(tmp_path: Path, cidr: str) -> None:
    ids = _ids(_write(tmp_path / "t", SG_V6 % cidr))
    assert ("SEC-AWS-SG-001", "aws_security_group.sg") in ids


def test_a_real_ipv6_range_is_not_world_open(tmp_path: Path) -> None:
    ids = _ids(_write(tmp_path / "t", SG_V6 % "2001:db8::/32"))
    assert not any(i == "SEC-AWS-SG-001" for i, _ in ids)


# ---- GCP firewall with no source ----------------------------------------------

GCP_FW = """\
resource "google_compute_firewall" "fw" {
  name    = "fw"
  network = "default"
%s
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
"""


def test_gcp_ingress_with_no_source_is_world_open(tmp_path: Path) -> None:
    # Google Cloud defaults an ingress rule with no source to 0.0.0.0/0.
    ids = _ids(_write(tmp_path / "t", GCP_FW % ""))
    assert ("SEC-GCP-NETWORK-001", "google_compute_firewall.fw") in ids


@pytest.mark.parametrize(
    "source",
    [
        '  source_tags = ["bastion"]',
        '  source_service_accounts = ["sa@p.iam.gserviceaccount.com"]',
        '  source_ranges = ["10.0.0.0/8"]',
    ],
)
def test_gcp_ingress_with_a_source_is_not_world_open(
    tmp_path: Path, source: str
) -> None:
    ids = _ids(_write(tmp_path / "t", GCP_FW % source))
    assert not any(i == "SEC-GCP-NETWORK-001" for i, _ in ids)


# ---- IAM action names are case-insensitive ------------------------------------

IAM = """\
resource "aws_iam_policy" "p" {
  name   = "p"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "%s", Resource = "%s" }]
  })
}
"""


def test_iam_wildcard_in_any_case_is_caught(tmp_path: Path) -> None:
    ids = _ids(_write(tmp_path / "t", IAM % ("IAM:*", "*")))
    assert ("SEC-AWS-IAM-JSON-002", "aws_iam_policy.p") in ids


def test_read_only_list_actions_in_any_case_are_not_a_wildcard_grant(
    tmp_path: Path,
) -> None:
    ids = _ids(_write(tmp_path / "t", IAM % ("EC2:DescribeInstances", "*")))
    assert not any(i == "SEC-AWS-IAM-001" for i, _ in ids)


# ---- Azure SQL firewall range --------------------------------------------------

AZ_SQL = """\
resource "azurerm_mssql_firewall_rule" "r" {
  name             = "r"
  server_id        = "x"
  start_ip_address = "%s"
  end_ip_address   = "%s"
}
"""


@pytest.mark.parametrize(
    "start,end",
    [
        ("0.0.0.0", "255.255.255.255"),
        ("0.0.0.1", "255.255.255.254"),  # the old exact-match bypass
        ("1.0.0.0", "200.0.0.0"),
    ],
)
def test_azure_sql_wide_range_fires(tmp_path: Path, start: str, end: str) -> None:
    ids = _ids(_write(tmp_path / "t", AZ_SQL % (start, end)))
    assert ("SEC-AZURE-SQL-002", "azurerm_mssql_firewall_rule.r") in ids


@pytest.mark.parametrize(
    "start,end",
    [
        ("203.0.113.0", "203.0.113.255"),
        ("255.255.255.0", "255.255.255.255"),  # matched the old end-address regex
        ("10.0.0.0", "10.255.255.255"),  # a /8 is the limit, not over it
    ],
)
def test_azure_sql_narrow_range_does_not_fire(
    tmp_path: Path, start: str, end: str
) -> None:
    ids = _ids(_write(tmp_path / "t", AZ_SQL % (start, end)))
    assert not any(i == "SEC-AZURE-SQL-002" for i, _ in ids)


# ---- S3 encryption linked through a local --------------------------------------

S3_LOCAL = """\
locals {
  bucket_name = "acme-data"
}
resource "aws_s3_bucket" "data" {
  bucket = local.bucket_name
}
%s
"""
S3_SSE = """\
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = %s
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""


def test_s3_encryption_linked_by_the_same_local_is_not_flagged(tmp_path: Path) -> None:
    ids = _ids(_write(tmp_path / "t", S3_LOCAL % (S3_SSE % "local.bucket_name")))
    assert not any(i == "SEC-AWS-S3-001" for i, _ in ids)


def test_s3_encryption_for_a_different_bucket_is_still_flagged(tmp_path: Path) -> None:
    ids = _ids(_write(tmp_path / "t", S3_LOCAL % (S3_SSE % "local.other_bucket")))
    assert ("SEC-AWS-S3-001", "aws_s3_bucket.data") in ids


# ---- EBS with account-level default encryption ---------------------------------

EBS = 'resource "aws_ebs_volume" "v" {\n  availability_zone = "eu-west-1a"\n  size = 10\n}\n'


@pytest.mark.parametrize("enabled,fires", [("true", False), ("false", True)])
def test_ebs_default_encryption_in_another_module(
    tmp_path: Path, enabled: str, fires: bool
) -> None:
    _write(tmp_path / "t" / "volumes", EBS)
    _write(
        tmp_path / "t" / "account",
        f'resource "aws_ebs_encryption_by_default" "on" {{\n  enabled = {enabled}\n}}\n',
    )
    ids = _ids(tmp_path / "t")
    assert (("SEC-AWS-EBS-001", "aws_ebs_volume.v") in ids) is fires


def test_ebs_without_default_encryption_is_flagged(tmp_path: Path) -> None:
    assert ("SEC-AWS-EBS-001", "aws_ebs_volume.v") in _ids(_write(tmp_path / "t", EBS))


def test_ebs_default_encryption_in_a_plan(tmp_path: Path) -> None:
    def plan(with_default: bool) -> Path:
        resources = [
            {
                "address": "aws_ebs_volume.v",
                "mode": "managed",
                "type": "aws_ebs_volume",
                "name": "v",
                "values": {"encrypted": False},
            }
        ]
        if with_default:
            resources.append(
                {
                    "address": "aws_ebs_encryption_by_default.on",
                    "mode": "managed",
                    "type": "aws_ebs_encryption_by_default",
                    "name": "on",
                    "values": {"enabled": True},
                }
            )
        p = tmp_path / f"plan-{with_default}.json"
        p.write_text(
            json.dumps(
                {
                    "format_version": "1.0",
                    "planned_values": {"root_module": {"resources": resources}},
                }
            )
        )
        return p

    empty = tmp_path / "empty"
    empty.mkdir()
    assert any(
        i == "SEC-AWS-EBS-001" for i, _ in _ids(empty, "--plan-json", str(plan(False)))
    )
    assert not any(
        i == "SEC-AWS-EBS-001" for i, _ in _ids(empty, "--plan-json", str(plan(True)))
    )


# ---- retired and corrected rules ------------------------------------------------


def test_gcp_deprecation_rule_is_retired(tmp_path: Path) -> None:
    """None of its arguments is deprecated in the google provider, and it
    fired on the secure `enable_legacy_abac = false`."""
    target = _write(
        tmp_path / "t",
        """\
resource "google_container_cluster" "c" {
  name               = "c"
  location           = "europe-west1"
  enable_legacy_abac = false
}
""",
    )
    assert not any(i == "STK-GCP-DEPRECATION-001" for i, _ in _ids(target))


@pytest.mark.parametrize("rule", ["SEC-AWS-IAM-JSON-003", "SEC-AWS-IAM-POLICY-005"])
def test_admin_rules_do_not_recommend_attaching_administrator_access(rule: str) -> None:
    """Attaching the managed AdministratorAccess policy grants the same
    access; recommending it cleared the finding without fixing anything."""
    text = (REPO / "catalog" / f"{rule}.yaml").read_text()
    assert (
        "attach\n  `arn:aws:iam::aws:policy/AdministratorAccess` directly" not in text
    )
    assert "is not a fix" in text
