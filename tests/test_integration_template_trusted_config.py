"""The copy-paste workflow template reads tf-analyze's config from the base branch.

`integrations/github-action.yml` runs the engine on the PR's own checkout,
so a PR could add `ignore_rules`, an ignore file or an emptied `rules_dir`
and switch off the scan that checks it. The template's step replaces those
files with the base branch's copies before the scan; it edits the checkout
rather than passing flags, so it works with old engine releases (`ref`).
These tests run the real step against a throwaway git repo.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"
TEMPLATE = yaml.safe_load(
    (REPO_ROOT / "integrations" / "github-action.yml").read_text()
)
STEPS = TEMPLATE["jobs"]["analyze"]["steps"]
STEP_NAME = "Use the base branch's tf-analyze config"

OPEN_SG = """resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

CUSTOM_RULE = (REPO_ROOT / "catalog" / "SEC-AWS-SG-001.yaml").read_text().replace(
    "id: SEC-AWS-SG-001", "id: CUSTOM-SG-001", 1)


def _step(name: str) -> dict:
    return next(s for s in STEPS if s.get("name") == name)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path, base: dict[str, str], pr: dict[str, str | None]) -> Path:
    """A repo whose origin `main` holds `base` and whose working tree holds `pr`
    on top (a `None` value deletes the file)."""
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
        path = repo / rel
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return repo


def _run_step(repo: Path, base_ref: str = "main", ok: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["bash", "-e", "-c", _step(STEP_NAME)["run"]],
        cwd=repo,
        env={**os.environ, "TFA_BASE_REF": base_ref},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (proc.returncode == 0) == ok, proc.stderr
    return proc


def _rule_ids(repo: Path) -> set[str]:
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(repo), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {f["id"] for f in json.loads(proc.stdout)["findings"]}


def test_step_runs_only_on_pull_requests_and_before_the_scan() -> None:
    names = [s.get("name") for s in STEPS]
    assert names.index(STEP_NAME) < names.index("Run tf-analyze")
    assert _step(STEP_NAME)["if"] == "github.event_name == 'pull_request'"
    # The base ref reaches the shell through env, not a template expression.
    assert "${{" not in _step(STEP_NAME)["run"]


def test_pr_cannot_add_ignore_rules(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG},
        pr={".tf-analyze.yaml": "ignore_rules:\n  - SEC-AWS-SG-001\n"},
    )
    assert "SEC-AWS-SG-001" not in _rule_ids(repo)
    _run_step(repo)
    assert not (repo / ".tf-analyze.yaml").exists()
    assert "SEC-AWS-SG-001" in _rule_ids(repo)


def test_pr_cannot_add_or_widen_an_ignore_file(tmp_path: Path) -> None:
    hide = "suppressions:\n  - id: SEC-AWS-SG-001\n    reason: pr\n"
    repo = _repo(
        tmp_path, base={"main.tf": OPEN_SG}, pr={".tf-analyze-ignore.yaml": hide}
    )
    assert "SEC-AWS-SG-001" not in _rule_ids(repo)
    _run_step(repo)
    assert "SEC-AWS-SG-001" in _rule_ids(repo)


def test_base_branch_settings_still_apply(tmp_path: Path) -> None:
    cfg = "ignore_rules:\n  - SEC-AWS-SG-001\n"
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG, ".tf-analyze.yaml": cfg},
        pr={".tf-analyze.yaml": None},
    )
    _run_step(repo)
    assert (repo / ".tf-analyze.yaml").read_text() == cfg
    assert "SEC-AWS-SG-001" not in _rule_ids(repo)


def test_rules_dir_comes_from_the_base_branch(tmp_path: Path) -> None:
    cfg = "rules_dir: rules\nignore_rules:\n  - SEC-AWS-SG-001\n"
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG, ".tf-analyze.yaml": cfg, "rules/CUSTOM-SG-001.yaml": CUSTOM_RULE},
        # The PR turns the custom rule into a stub and adds one of its own.
        pr={"rules/CUSTOM-SG-001.yaml": CUSTOM_RULE.replace("status: active", "status: stub"),
            "rules/CUSTOM-PR-001.yaml": CUSTOM_RULE.replace("CUSTOM-SG-001", "CUSTOM-PR-001")},
    )
    assert "CUSTOM-SG-001" not in _rule_ids(repo)
    _run_step(repo)
    assert (repo / "rules" / "CUSTOM-SG-001.yaml").read_text() == CUSTOM_RULE
    assert not (repo / "rules" / "CUSTOM-PR-001.yaml").exists()
    ids = _rule_ids(repo)
    assert "CUSTOM-SG-001" in ids and "CUSTOM-PR-001" not in ids


def test_rules_dir_outside_the_checkout_is_not_touched(tmp_path: Path) -> None:
    outside = tmp_path / "keep"
    outside.mkdir()
    (outside / "f").write_text("x")
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG, ".tf-analyze.yaml": "rules_dir: ../keep\n"},
        pr={},
    )
    _run_step(repo)
    assert (outside / "f").exists()


def test_a_symlink_on_the_rules_dir_path_stops_the_scan(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "rules").mkdir(parents=True)
    (outside / "rules" / "keep").write_text("x")
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG, ".tf-analyze.yaml": "rules_dir: cfg/rules\n",
                                 "cfg/rules/CUSTOM-SG-001.yaml": CUSTOM_RULE}, pr={})
    shutil.rmtree(repo / "cfg")
    (repo / "cfg").symlink_to(outside)
    proc = _run_step(repo, ok=False)
    assert "is a symlink" in proc.stdout
    assert (outside / "rules" / "keep").exists()
    assert not (outside / "rules" / "CUSTOM-SG-001.yaml").exists()


def test_a_base_change_reruns_the_scan() -> None:
    assert "edited" in TEMPLATE[True]["pull_request"]["types"]


def test_unreadable_base_drops_the_pr_config(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        base={"main.tf": OPEN_SG},
        pr={".tf-analyze.yaml": "ignore_rules:\n  - SEC-AWS-SG-001\n"},
    )
    proc = _run_step(repo, base_ref="no-such-branch")
    assert "cannot read base branch" in proc.stdout
    assert not (repo / ".tf-analyze.yaml").exists()
    assert "SEC-AWS-SG-001" in _rule_ids(repo)


def test_a_tag_named_like_the_base_cannot_stand_in_for_it(tmp_path: Path) -> None:
    repo = _repo(tmp_path, base={"main.tf": OPEN_SG}, pr={})
    (repo / ".tf-analyze.yaml").write_text("ignore_rules:\n  - SEC-AWS-SG-001\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    _git(repo, "tag", "origin/main")
    _run_step(repo)
    assert "SEC-AWS-SG-001" in _rule_ids(repo)


def test_inline_comment_escaping_matches_the_engine() -> None:
    """The template's mdText / fence give the same output as _md_text / _md_fence."""
    if not shutil.which("node"):
        pytest.skip("node not installed")
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from _output import _md_fence, _md_text

    script = next(
        s["with"]["script"]
        for s in STEPS
        if "mdText" in (s.get("with") or {}).get("script", "")
    )
    start = script.index("const mdText")
    end = script.index("\n", script.index("const fence"))
    samples = [
        "[x](https://e.vil) @someone <img src=x>",
        "## heading",
        "&#64;someone",
        "Missing `x` on `y`",
        "``[a](https://e.vil)`",
    ]
    fix = "a\n```\n![x](https://e.vil)\n````"
    prog = (
        script[start:end]
        + "\nconst S = "
        + json.dumps(samples)
        + ";\n"
        + "console.log(JSON.stringify({t: S.map(mdText), f: fence("
        + json.dumps(fix)
        + ")}));"
    )
    out = json.loads(
        subprocess.run(
            ["node", "-e", prog], capture_output=True, text=True, check=True
        ).stdout
    )
    assert out["t"] == [_md_text(s) for s in samples]
    assert out["f"] == _md_fence(fix)[0]
    body = script[
        script.index("const body = [") : script.index(
            "].join('\\n');", script.index("const body = [")
        )
    ]
    assert "mdText(finding.title)" in body and "'```suggestion'" not in body


def test_a_rules_dir_rule_cannot_use_a_built_in_id(tmp_path: Path) -> None:
    """PR comments plain-text a recommendation from a `CUSTOM-` rule only;
    that is safe because rules_dir rules must use the prefix. A rules_dir
    rule claiming a built-in id is skipped, so it can't pass as trusted."""
    imposter = CUSTOM_RULE.replace("id: CUSTOM-SG-001", "id: SEC-AWS-IMPOSTER-001", 1)
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "x.yaml").write_text(imposter)
    (tmp_path / ".tf-analyze.yaml").write_text("rules_dir: rules\n")
    (tmp_path / "main.tf").write_text(OPEN_SG)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    assert "does not start with 'CUSTOM-'; skipping" in proc.stderr
    assert "SEC-AWS-IMPOSTER-001" not in {f["id"] for f in json.loads(proc.stdout)["findings"]}
