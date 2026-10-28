"""Variable / output / provider / version robustness rules read code, not
comments: a commented-out reference, entry or block no longer decides a
finding. A variable's mention of itself in its own ``validation`` block
is not a use, and a provider alias named in a string is not a use."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _ids(tmp_path: Path, files: dict[str, str]) -> list[str]:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return [f["id"] for f in json.loads(out.stdout)["findings"]]


# ---- ROB-UNUSED-001 (variable_unused) -----------------------------------------


def test_commented_reference_is_not_a_use(tmp_path) -> None:
    text = 'variable "x" {\n  type = string\n}\n# value = var.x\n'
    assert "ROB-UNUSED-001" in _ids(tmp_path, {"main.tf": text})


def test_own_validation_is_not_a_use(tmp_path) -> None:
    text = (
        'variable "x" {\n'
        "  type = string\n"
        "  validation {\n"
        "    condition     = length(var.x) > 0\n"
        '    error_message = "x must not be empty"\n'
        "  }\n"
        "}\n"
    )
    assert "ROB-UNUSED-001" in _ids(tmp_path, {"main.tf": text})


def test_other_variables_validation_and_heredoc_are_uses(tmp_path) -> None:
    text = (
        'variable "x" {\n  type = string\n}\n'
        'variable "y" {\n'
        "  type = string\n"
        "  validation {\n"
        "    condition     = var.y != var.x\n"
        '    error_message = "y must differ from x"\n'
        "  }\n"
        "}\n"
        'resource "aws_instance" "i" {\n'
        "  user_data = <<EOT\n"
        "echo ${var.y}\n"
        "EOT\n"
        "}\n"
    )
    assert "ROB-UNUSED-001" not in _ids(tmp_path, {"main.tf": text})


# ---- ROB-UNUSED-002 (output_unused) -------------------------------------------


def test_commented_module_output_reference_is_not_a_use(tmp_path) -> None:
    files = {
        "main.tf": 'module "child" {\n  source = "./child"\n}\n# v = module.child.out\n',
        "child/main.tf": 'output "out" {\n  value = 1\n}\n',
    }
    assert "ROB-UNUSED-002" in _ids(tmp_path, files)


# ---- ROB-PROVIDER-ALIAS-002 / -001 --------------------------------------------


def test_alias_named_in_a_string_is_unused(tmp_path) -> None:
    text = (
        'provider "aws" {\n  alias = "west"\n}\n'
        'resource "aws_s3_bucket" "b" {\n  bucket = "aws.west"\n}\n'
    )
    assert "ROB-PROVIDER-ALIAS-002" in _ids(tmp_path, {"main.tf": text})


def test_alias_used_by_provider_argument(tmp_path) -> None:
    text = (
        'provider "aws" {\n  alias = "west"\n}\n'
        'resource "aws_s3_bucket" "b" {\n  provider = aws.west\n}\n'
    )
    assert "ROB-PROVIDER-ALIAS-002" not in _ids(tmp_path, {"main.tf": text})


def test_commented_providers_entry_is_not_passed(tmp_path) -> None:
    files = {
        "main.tf": (
            'provider "aws" {\n  alias = "west"\n}\n'
            'module "m" {\n'
            '  source = "./m"\n'
            "  providers = {\n"
            "    # aws = aws.east\n"
            "    aws = aws.west\n"
            "  }\n"
            "}\n"
        ),
        "m/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
    }
    assert "ROB-PROVIDER-ALIAS-001" not in _ids(tmp_path, files)


# ---- ROB-BACKEND-001 (backend_inconsistency) -----------------------------------


def test_backend_in_block_comment_is_not_configured(tmp_path) -> None:
    text = (
        'terraform {\n  backend "s3" {\n    bucket       = "b"\n    use_lockfile = true\n  }\n}\n'
        '/*\nterraform {\n  backend "local" {}\n}\n*/\n'
    )
    assert "ROB-BACKEND-001" not in _ids(tmp_path, {"main.tf": text})


# ---- ROB-VERSION-003 / -002 / -001 ---------------------------------------------


def test_commented_provider_entry_needs_no_version(tmp_path) -> None:
    text = (
        "terraform {\n"
        '  required_version = ">= 1.6"\n'
        "  required_providers {\n"
        '    aws = {\n      source  = "hashicorp/aws"\n      version = "~> 5.0"\n    }\n'
        '    # google = {\n    #   source = "hashicorp/google"\n    # }\n'
        "  }\n"
        "}\n"
    )
    assert "ROB-VERSION-003" not in _ids(tmp_path, {"versions.tf": text})


def test_commented_provider_version_does_not_count(tmp_path) -> None:
    text = (
        "terraform {\n"
        '  required_version = ">= 1.6"\n'
        "  required_providers {\n"
        '    aws = {\n      source = "hashicorp/aws"\n      # version = "~> 5.0"\n    }\n'
        "  }\n"
        "}\n"
    )
    assert "ROB-VERSION-003" in _ids(tmp_path, {"versions.tf": text})


def test_commented_required_version_does_not_count(tmp_path) -> None:
    text = '# required_version = ">= 1.6"\nresource "aws_s3_bucket" "b" {}\n'
    assert "ROB-VERSION-002" in _ids(tmp_path, {"main.tf": text})


def test_old_required_version_outside_versions_tf(tmp_path) -> None:
    text = 'terraform {\n  required_version = ">= 0.12"\n}\n'
    assert "ROB-VERSION-001" in _ids(tmp_path, {"main.tf": text})
