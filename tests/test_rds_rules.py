"""RDS rules follow what the AWS provider actually sends.

ROB-AWS-RDS-001: an `aws_db_instance` without `backup_retention_period` is
created with 0 (the provider sends the zero value), but an `aws_rds_cluster`
without it gets AWS's default of 1 day (the provider omits it, and Aurora
can't turn backups off), so clusters are not flagged. Read replicas take
backups and encryption from their source; snapshot restores and Aurora
Serverless v1 take encryption from the snapshot / are always encrypted.
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
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


def _res(rtype: str, body: str) -> str:
    return f'resource "{rtype}" "r" {{\n{body}\n}}\n'


@pytest.mark.parametrize(("body", "fires"), [
    ("  engine = \"postgres\"", True),
    ("  backup_retention_period = 0", True),
    ("  backup_retention_period = 7", False),
    ('  replicate_source_db = "arn:aws:rds:eu-west-2:1:db:primary"', False),
    ('  replicate_source_db = "primary"\n  backup_retention_period = 0', False),
])
def test_instance_backup_retention(tmp_path, body, fires) -> None:
    assert ("ROB-AWS-RDS-001" in _ids(tmp_path, _res("aws_db_instance", body))) is fires


@pytest.mark.parametrize("body", ['  engine = "aurora-postgresql"', "  backup_retention_period = 0"])
def test_aurora_cluster_backups_are_not_flagged(tmp_path, body) -> None:
    assert "ROB-AWS-RDS-001" not in _ids(tmp_path, _res("aws_rds_cluster", body))


@pytest.mark.parametrize(("rtype", "body", "fires"), [
    ("aws_db_instance", '  engine = "postgres"', True),
    ("aws_db_instance", "  storage_encrypted = false", True),
    ("aws_db_instance", "  storage_encrypted = true", False),
    ("aws_db_instance", '  replicate_source_db = "primary"', False),
    ("aws_db_instance", '  snapshot_identifier = "snap-1"', False),
    ("aws_rds_cluster", '  engine = "aurora-mysql"', True),
    ("aws_rds_cluster", '  engine_mode = "provisioned"', True),
    ("aws_rds_cluster", '  engine_mode = "serverless"', False),
    ("aws_rds_cluster", '  snapshot_identifier = "snap-1"', False),
    ("aws_rds_cluster", '  replication_source_identifier = "arn:aws:rds:us-east-1:1:cluster:a"', False),
    ("aws_rds_cluster", '  engine_mode = "serverless"\n  storage_encrypted = false', True),
])
def test_storage_encryption(tmp_path, rtype, body, fires) -> None:
    assert ("SEC-AWS-RDS-002" in _ids(tmp_path, _res(rtype, body))) is fires


def test_suppress_if_list_holds_when_any_entry_does() -> None:
    sys.path.insert(0, str(DETECT.parent))
    from _plan_state import _plan_suppressed

    spec = [{"arg": "engine_mode", "equals": "serverless"}, {"arg": "snapshot_identifier", "regex": "."}]
    assert _plan_suppressed(spec, {"snapshot_identifier": "s"})
    assert _plan_suppressed(spec, {"engine_mode": "SERVERLESS"})
    assert not _plan_suppressed(spec, {"engine_mode": "provisioned"})
