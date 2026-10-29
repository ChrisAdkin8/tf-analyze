"""Hardcoded secrets outside resource blocks are reported (critical review).

The entropy rule only walked `resource` blocks, and SEC-SECRETS-001's
name list missed `secret_key`, `private_key`, `*token` and quoted map
keys, so a provider's `secret_key = "..."`, a GitHub `token = "ghp_..."`
and a `locals` map entry `"password" = "..."` were all silent.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _findings(tmp_path: Path, hcl: str, name: str = "main.tf") -> list[dict]:
    (tmp_path / name).write_text(hcl)
    proc = subprocess.run(
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
    assert proc.returncode in (0, 1), proc.stderr
    return json.loads(proc.stdout)["findings"]


def _ids_at(findings: list[dict]) -> set[tuple[str, int]]:
    return {(f["id"], f["line"]) for f in findings if f["id"].startswith("SEC-SECRETS")}


def test_provider_credentials_are_reported(tmp_path) -> None:
    hcl = (
        'provider "aws" {\n'
        '  region     = "us-east-1"\n'
        '  secret_key = "q8Zt3LmP0vXr7Nc2Wb9Hs4Kd1Fg6Jy5Ua0Te8Ri3"\n'
        "}\n"
        'provider "github" {\n'
        '  token = "ghp_R7x2Lq9Zt4Mv8Nc3Wb6Hs1Kd5Fg0Jy2Ua7Pq"\n'
        "}\n"
    )
    found = _findings(tmp_path, hcl)
    assert _ids_at(found) == {
        ("SEC-SECRETS-001", 3),
        ("SEC-SECRETS-ENTROPY-001", 3),
        ("SEC-SECRETS-001", 6),
        ("SEC-SECRETS-ENTROPY-001", 6),
    }
    assert {
        f.get("resource") for f in found if f["id"] == "SEC-SECRETS-ENTROPY-001"
    } == {
        "provider.aws",
        "provider.github",
    }


@pytest.mark.parametrize(
    "line",
    [
        '  "password" = "AnotherHardcoded99"',
        '  private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"',
        '  access_token = "xoxb-1234567890-abcdefghij"',
    ],
)
def test_locals_credentials_are_reported(tmp_path, line) -> None:
    hcl = "locals {\n  creds = {\n" + line + "\n  }\n}\n"
    assert ("SEC-SECRETS-001", 3) in _ids_at(_findings(tmp_path, hcl))


def test_entropy_rule_checks_module_inputs(tmp_path) -> None:
    hcl = (
        'module "app" {\n'
        '  source  = "./app"\n'
        '  api_key_value = "Zq8Lm3Pv0Xr7Nc2Wb9Hs4Kd1Fg6Jy5U"\n'
        "}\n"
    )
    found = _findings(tmp_path, hcl)
    assert {
        (f["id"], f.get("resource"))
        for f in found
        if f["id"] == "SEC-SECRETS-ENTROPY-001"
    } == {
        ("SEC-SECRETS-ENTROPY-001", "module.app"),
    }


@pytest.mark.parametrize(
    "line",
    [
        "  token = var.github_token",
        '  token = "${var.github_token}"',
        "  secret_key = data.aws_secretsmanager_secret_version.k.secret_string",
    ],
)
def test_references_are_not_reported(tmp_path, line) -> None:
    hcl = 'provider "github" {\n' + line + "\n}\n"
    assert _ids_at(_findings(tmp_path, hcl)) == set()


def test_tfvars_json_token_is_reported(tmp_path) -> None:
    (tmp_path / "main.tf").write_text('variable "github_token" {}\n')
    found = _findings(
        tmp_path,
        '{"github_token": "ghp_R7x2Lq9Zt4Mv8Nc3Wb6Hs1Kd5Fg0Jy2Ua7Pq"}\n',
        name="prod.tfvars.json",
    )
    assert "SEC-SECRETS-001" in {f["id"] for f in found}
