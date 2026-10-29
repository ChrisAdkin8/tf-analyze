"""What counts as production: whole words, not the letters "prod" anywhere.

OPS-ENV-001 treated any path containing "prod" as production, so nonprod/,
preprod/ and products/ fired, and both it and the intent-gap rules
(INT-INTENT-003/004) read `environment = "prod..."` from raw text, so a
commented-out label or "prodigy" counted too.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"

# OPS-ENV-001 covers GCP types that take `deletion_protection`.
DB = 'resource "google_sql_database_instance" "db" {\n  database_version = "POSTGRES_15"\n%s}\n'


def _ids(target: Path) -> set[str]:
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(target), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return root


@pytest.mark.parametrize(
    "folder", ["prod", "production", "envs/prod-eu", "eu-prd", "live/prod"]
)
def test_a_production_folder_counts(tmp_path, folder) -> None:
    assert "OPS-ENV-001" in _ids(_write(tmp_path, f"{folder}/main.tf", DB % ""))


@pytest.mark.parametrize(
    "folder", ["nonprod", "preprod", "pre-prod", "non_prod", "products", "reproduce"]
)
def test_a_folder_that_only_contains_prod_does_not(tmp_path, folder) -> None:
    assert "OPS-ENV-001" not in _ids(_write(tmp_path, f"{folder}/main.tf", DB % ""))


def test_folders_above_the_target_do_not_count(tmp_path) -> None:
    target = tmp_path / "prod" / "repo"
    assert "OPS-ENV-001" not in _ids(_write(target, "main.tf", DB % ""))


def test_a_production_file_name_counts(tmp_path) -> None:
    assert "OPS-ENV-001" in _ids(_write(tmp_path, "prod.tf", DB % ""))


@pytest.mark.parametrize(
    ("label", "fires"),
    [
        ('  labels = {\n    environment = "production"\n  }\n', True),
        ('  labels = { env = "prod-eu" }\n', True),
        ('  labels = {\n    environment = "nonprod"\n  }\n', False),
        ('  labels = {\n    environment = "prodigy"\n  }\n', False),
        ('  # labels = { environment = "prod" }\n', False),
    ],
)
def test_environment_labels_are_words(tmp_path, label, fires) -> None:
    assert ("OPS-ENV-001" in _ids(_write(tmp_path, "main.tf", DB % label))) is fires


@pytest.mark.parametrize(
    ("label", "fires"),
    [
        ('Environment = "prod"', True),
        ('Environment = "preprod"', False),
        ('# Environment = "prod"', False),
    ],
)
def test_intent_gap_reads_the_label_the_same_way(tmp_path, label, fires) -> None:
    hcl = (
        'resource "aws_s3_bucket" "b" {\n  bucket        = "b"\n  force_destroy = true\n'
        f"  tags = {{\n    {label}\n  }}\n}}\n"
    )
    assert ("INT-INTENT-004" in _ids(_write(tmp_path, "main.tf", hcl))) is fires


def test_a_commented_out_force_destroy_does_not_count(tmp_path) -> None:
    hcl = (
        'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  # force_destroy = true\n'
        '  tags = { Environment = "prod" }\n}\n'
    )
    assert "INT-INTENT-004" not in _ids(_write(tmp_path, "main.tf", hcl))
