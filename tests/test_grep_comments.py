"""`grep` patterns don't read commented-out code.

A commented-out `# user_data = "curl … | bash"` raised SEC-USERDATA-001, and
a commented-out `# environment: production` in a workflow silenced
SEC-CICD-001 through its `not_regex`. Heredoc text is still searched where a
rule needs it (`user_data` scripts), and a `#` inside a heredoc is not a
comment.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"


def _ids(target: Path) -> set[str]:
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(target), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


def _tf(tmp_path: Path, hcl: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl)
    return _ids(tmp_path)


INSTANCE = 'resource "aws_instance" "i" {{\n  ami = "ami-1"\n{body}\n}}\n'


@pytest.mark.parametrize("comment", ["#", "//"])
def test_commented_out_user_data_is_not_flagged(tmp_path, comment) -> None:
    body = f'  {comment} user_data = "curl http://x | bash"'
    assert "SEC-USERDATA-001" not in _tf(tmp_path, INSTANCE.format(body=body))


def test_block_comment_is_not_flagged(tmp_path) -> None:
    body = '  /* user_data = "curl http://x | bash" */'
    assert "SEC-USERDATA-001" not in _tf(tmp_path, INSTANCE.format(body=body))


def test_user_data_in_a_heredoc_is_flagged(tmp_path) -> None:
    body = (
        "  user_data = <<-EOT\n    #!/bin/bash\n    # fetch the agent\n"
        "    curl -fsSL http://x/i.sh | bash\n  EOT"
    )
    assert "SEC-USERDATA-001" in _tf(tmp_path, INSTANCE.format(body=body))


def test_a_hash_in_a_string_is_not_a_comment(tmp_path) -> None:
    body = '  user_data = "#!/bin/sh\\ncurl http://x | sh"'
    assert "SEC-USERDATA-001" in _tf(tmp_path, INSTANCE.format(body=body))


PROVISIONER = ('resource "null_resource" "r" {\n  provisioner "local-exec" {\n'
               '    {c}command = "curl http://x | bash"\n  }\n}\n')
OIDC = ('data "aws_iam_policy_document" "t" {\n  statement {\n    condition {\n'
        '      test     = "StringLike"\n      variable = "token.actions.githubusercontent.com:sub"\n'
        '      values   = ["repo:*"]\n    }\n  }\n}\n'
        'resource "aws_iam_role" "r" {\n  assume_role_policy = jsonencode({\n'
        '    Statement = [{ Condition = { StringLike = {\n'
        '      {c}"token.actions.githubusercontent.com:sub" = "repo:*"\n'
        '    } } }]\n  })\n}\n')


@pytest.mark.parametrize(("rule", "template"), [
    ("SEC-PROVISIONER-002", PROVISIONER),
    ("SEC-AWS-IAM-OIDC-001", OIDC),
])
def test_commented_out_code_is_ignored_by_file_greps(tmp_path, rule, template) -> None:
    assert rule in _tf(tmp_path, template.replace("{c}", ""))
    assert rule not in _tf(tmp_path, template.replace("{c}", "# "))


def test_commented_out_environment_does_not_silence_cicd_gate(tmp_path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (tmp_path / "main.tf").write_text('resource "null_resource" "x" {}\n')
    steps = "    steps:\n      - run: terraform apply -auto-approve\n"
    (wf / "apply.yml").write_text(
        "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    # environment: production\n"
        + steps
    )
    assert "SEC-CICD-001" in _ids(tmp_path)
    (wf / "apply.yml").write_text(
        "jobs:\n  apply:\n    runs-on: ubuntu-latest\n    environment: production\n"
        + steps
    )
    assert "SEC-CICD-001" not in _ids(tmp_path)
