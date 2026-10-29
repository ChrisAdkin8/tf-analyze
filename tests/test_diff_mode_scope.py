"""`--mode diff` scans everything a change can affect (critical review).

* A PR that only flips a variable default in `variables.tf`, or a value in
  a `.tfvars`, re-scanned nothing that used it, and the gate passed.
* With `--target` a subfolder of the repo, untracked files were joined
  onto the repo root with a subfolder-relative path, didn't exist, and
  were dropped without a warning.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _diff

REPO = Path(__file__).resolve().parents[1]

RDS = (
    'resource "aws_db_instance" "db" {\n'
    '  engine              = "mysql"\n'
    "  publicly_accessible = var.public\n"
    "}\n"
)
VARS = 'variable "public" {\n  default = %s\n}\n'
RULE = "SEC-AWS-RDS-001"  # publicly_accessible = true


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=str(repo), check=True, capture_output=True, text=True
    )


def _repo(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "switch", "-q", "-c", "pr")
    return root


def _commit(repo: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (repo / name).write_text(text)
    _git(repo, "commit", "-q", "-am", "pr")


def _diff_scan(target: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--mode",
            "diff",
            "--diff-base",
            "main",
            "--fail-on",
            "HIGH",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _ids(proc: subprocess.CompletedProcess) -> set[str]:
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


def test_variable_default_change_rescans_its_users(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": RDS, "variables.tf": VARS % "false"})
    _commit(repo, {"variables.tf": VARS % "true"})
    proc = _diff_scan(repo)
    assert RULE in _ids(proc), proc.stderr
    assert proc.returncode == 1


def test_tfvars_change_rescans_its_module(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": RDS,
            "variables.tf": VARS % "false",
            "terraform.tfvars": "public = false\n",
        },
    )
    _commit(repo, {"terraform.tfvars": "public = true\n"})
    assert RULE in _ids(_diff_scan(repo))


def test_a_resource_only_change_stays_scoped_to_its_file(tmp_path) -> None:
    # main.tf declares no variable/locals, so its folder-mates aren't pulled in.
    other = 'resource "aws_db_instance" "old" {\n  publicly_accessible = true\n}\n'
    repo = _repo(
        tmp_path / "r",
        {"main.tf": RDS, "variables.tf": VARS % "false", "old.tf": other},
    )
    _commit(repo, {"main.tf": RDS.replace('"mysql"', '"postgres"')})
    files = _diff.get_diff_files(repo, "main")
    assert files == {(repo / "main.tf").resolve()}


def test_untracked_file_in_a_subfolder_target_is_scanned(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"README.md": "x\n", "infra/base.tf": "locals {}\n"})
    (repo / "infra" / "new.tf").write_text(
        'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n'
    )
    assert (repo / "infra" / "new.tf").resolve() in _diff.get_diff_files(
        repo / "infra", "main"
    )
    proc = _diff_scan(repo / "infra")
    assert RULE in _ids(proc), proc.stderr


BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
PAB = (
    'resource "aws_s3_bucket_public_access_block" "b" {\n'
    "  bucket                  = aws_s3_bucket.b.id\n"
    "  block_public_acls       = true\n"
    "  block_public_policy     = true\n"
    "  ignore_public_acls      = true\n"
    "  restrict_public_buckets = true\n"
    "}\n"
)


def test_moving_a_file_out_rescans_the_folder_it_left(tmp_path) -> None:
    # git reports a move under its new path only; the bucket left behind
    # in infra/ lost its public access block.
    repo = _repo(tmp_path / "r", {"infra/main.tf": BUCKET, "infra/pab.tf": PAB})
    (repo / "other").mkdir()
    _git(repo, "mv", "infra/pab.tf", "other/pab.tf")
    _git(repo, "commit", "-q", "-m", "move")
    assert "SEC-AWS-S3-PUBLIC-BLOCK-001" in _ids(_diff_scan(repo))


def test_caller_change_rescans_its_local_child_module(tmp_path) -> None:
    caller = 'module "db" {\n  source = "./modules/db"\n  public = %s\n}\n'
    child = 'variable "public" {}\n' + RDS
    repo = _repo(
        tmp_path / "r", {"main.tf": caller % "false", "modules/db/main.tf": child}
    )
    _commit(repo, {"main.tf": caller % "true"})
    assert (repo / "modules" / "db" / "main.tf").resolve() in _diff.get_diff_files(
        repo, "main"
    )
    assert RULE in _ids(_diff_scan(repo))
