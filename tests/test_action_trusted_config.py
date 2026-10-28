"""On pull requests the action reads tf-analyze's config from the base branch.

The PR controls every file in its checkout, including `.tf-analyze.yaml`
(ignore_rules / ignore_paths / rules_dir) and `.tf-analyze-ignore.yaml`, so
it could use them to switch off the gate that checks it. The action copies
the base branch's versions into a folder the scan mounts read-only and passes
them with `--config` / `--ignore-file`. These tests run the real step scripts
against a throwaway git repo, then run the engine the way the action does.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"
ACTION = yaml.safe_load((REPO_ROOT / "action.yml").read_text())

OPEN_SG = """resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def _step(name: str) -> dict:
    return next(s for s in ACTION["runs"]["steps"] if s.get("name") == name)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path, base: dict[str, str], pr: dict[str, str]) -> Path:
    """A repo whose `origin/main` holds `base` and whose working tree holds `pr`."""
    repo = tmp_path / "ws"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    for rel, text in base.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "base")
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")
    for rel, text in pr.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    return repo


def _run_trusted(repo: Path, tmp_path: Path, target: str = ".",
                 base_ref: str = "main") -> dict[str, str]:
    out = tmp_path / "gh_output"
    out.write_text("")
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir(exist_ok=True)
    proc = subprocess.run(
        ["bash", "-c", _step("Use the base branch's tf-analyze config")["run"]],
        env={
            **os.environ,
            "TFA_TARGET": target,
            "TFA_BASE_REF": base_ref,
            "TFA_WORKSPACE": str(repo),
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(out),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return dict(
        line.split("=", 1) for line in out.read_text().splitlines() if "=" in line
    )


def _engine_args(outputs: dict[str, str], repo: Path, target: str = ".") -> list[str]:
    """Translate the step's container paths (/trusted, /workspace) to local ones."""

    def local(p: str) -> str:
        return p.replace("/trusted", outputs["dir"], 1)

    args = ["--target", str(repo / target)]
    if outputs.get("config"):
        args += ["--config", local(outputs["config"])]
    else:
        args += ["--no-project-config"]
    args += ["--ignore-file", local(outputs["ignore"])]
    return args


def _rule_ids(args: list[str]) -> set[str]:
    import json

    proc = subprocess.run(
        [sys.executable, str(DETECT), *args, "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    data = json.loads(proc.stdout)
    return {f["id"] for f in data["findings"]}


def test_pr_cannot_add_ignore_rules(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG},
        pr={".tf-analyze.yaml": "ignore_rules:\n  - SEC-AWS-SG-001\n"},
    )
    # Sanity: honouring the PR's own config hides the finding.
    assert "SEC-AWS-SG-001" not in _rule_ids(["--target", str(repo)])
    outputs = _run_trusted(repo, tmp_path)
    assert "config" not in outputs  # the base branch has no config
    assert "SEC-AWS-SG-001" in _rule_ids(_engine_args(outputs, repo))


def test_pr_cannot_add_an_ignore_file(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG},
        pr={
            ".tf-analyze-ignore.yaml": "suppressions:\n  - id: SEC-AWS-SG-001\n    reason: x\n",
        },
    )
    assert "SEC-AWS-SG-001" not in _rule_ids(["--target", str(repo)])
    outputs = _run_trusted(repo, tmp_path)
    assert outputs["ignore"] == "/trusted/none"
    assert "SEC-AWS-SG-001" in _rule_ids(_engine_args(outputs, repo))


def test_base_branch_settings_still_apply(tmp_path: Path) -> None:
    base_cfg = "ignore_rules:\n  - SEC-AWS-SG-001\n"
    base_ignore = (
        "suppressions:\n  - id: OPS-AWS-TAGS-001\n    reason: tags via provider\n"
    )
    repo = _repo(
        tmp_path,
        base={
            "main.tf": OPEN_SG,
            ".tf-analyze.yaml": base_cfg,
            ".tf-analyze-ignore.yaml": base_ignore,
        },
        pr={
            ".tf-analyze.yaml": "# the PR deleted the base settings\n",
            ".tf-analyze-ignore.yaml": "suppressions: []\n",
        },
    )
    outputs = _run_trusted(repo, tmp_path)
    assert outputs["config"] == "/trusted/.tf-analyze.yaml"
    assert outputs["ignore"] == "/trusted/.tf-analyze-ignore.yaml"
    ids = _rule_ids(_engine_args(outputs, repo))
    assert "SEC-AWS-SG-001" not in ids
    assert "OPS-AWS-TAGS-001" not in ids


def test_subdirectory_target_and_rules_dir(tmp_path: Path) -> None:
    rule = (REPO_ROOT / "catalog" / "SEC-AWS-SG-001.yaml").read_text()
    repo = _repo(
        tmp_path,
        base={
            "infra/main.tf": OPEN_SG,
            "infra/.tf-analyze.yaml": 'rules_dir: "rules/"  # custom rules\n',
            "infra/rules/.keep": "",
            ".tf-analyze-ignore.yaml": "suppressions: []\n",
        },
        pr={"infra/rules/CUSTOM-X-001.yaml": rule},
    )
    outputs = _run_trusted(repo, tmp_path, target="infra")
    trusted = Path(outputs["dir"])
    assert outputs["config"] == "/trusted/infra/.tf-analyze.yaml"
    # The parent-folder fallback matches the engine's own lookup.
    assert outputs["ignore"] == "/trusted/.tf-analyze-ignore.yaml"
    assert (trusted / "infra" / "rules" / ".keep").exists()
    # A rule the PR added to rules_dir is not copied.
    assert not (trusted / "infra" / "rules" / "CUSTOM-X-001.yaml").exists()


def test_unreadable_base_fails_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG}, pr={})
    _git(repo, "remote", "set-url", "origin", str(tmp_path / "missing"))
    outputs = _run_trusted(repo, tmp_path)
    assert "config" not in outputs and outputs["ignore"] == "/trusted/none"


def test_args_step_passes_the_trusted_copies(tmp_path: Path) -> None:
    args_file = tmp_path / "base-args"
    script = _step("Build detect.py args")["run"].replace(
        "/tmp/tf-analyze-base-args", str(args_file)
    )
    env = {
        **os.environ,
        "TFA_TARGET": ".",
        "TFA_MODE_OUT": "diff",
        "GITHUB_OUTPUT": str(tmp_path / "o"),
        "TFA_TRUSTED_DIR": "/rt/tf-analyze-trusted",
        "TFA_TRUSTED_CONFIG": "",
        "TFA_TRUSTED_IGNORE": "/trusted/none",
    }
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    args = args_file.read_text().splitlines()
    assert "--no-project-config" in args
    assert args[args.index("--ignore-file") + 1] == "/trusted/none"
    env.update(TFA_TRUSTED_DIR="")
    subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True)
    args = args_file.read_text().splitlines()
    assert "--ignore-file" not in args and "--no-project-config" not in args


def test_trusted_step_only_runs_on_untrusted_prs() -> None:
    cond = _step("Use the base branch's tf-analyze config")["if"]
    assert "pull_request" in cond and "pull_request_target" in cond
    assert "inputs.trust-pr-config != 'true'" in cond
    assert ACTION["inputs"]["trust-pr-config"]["default"] == "false"
    scan = _step("Run tf-analyze (JSON)")["run"]
    assert '"${TFA_TRUSTED_DIR}:/trusted:ro"' in scan


def test_a_tag_named_like_the_base_cannot_stand_in_for_it(tmp_path: Path) -> None:
    """`origin/main` as a short name resolves to a tag of that name first."""
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG}, pr={})
    (repo / ".tf-analyze.yaml").write_text("ignore_rules:\n  - SEC-AWS-SG-001\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    _git(repo, "tag", "origin/main")
    outputs = _run_trusted(repo, tmp_path)
    assert "config" not in outputs
    assert "SEC-AWS-SG-001" in _rule_ids(_engine_args(outputs, repo))


def test_merge_queue_base_ref_is_a_full_ref(tmp_path: Path) -> None:
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG, ".tf-analyze.yaml": "ignore_paths: []\n"}, pr={})
    outputs = _run_trusted(repo, tmp_path, base_ref="refs/heads/main")
    assert outputs["config"] == "/trusted/.tf-analyze.yaml"
    cond = _step("Use the base branch's tf-analyze config")["if"]
    assert "merge_group" in cond
    env = _step("Use the base branch's tf-analyze config")["env"]["TFA_BASE_REF"]
    assert "github.event.merge_group.base_ref" in env
