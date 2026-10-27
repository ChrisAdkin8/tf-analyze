"""Untrusted pull-request hardening.

A scanner runs on Terraform from pull requests, including forks, so every
field a PR controls (file names, suppression reasons, comment text,
workflow inputs) must be treated as hostile. These tests pin the fixes:

- the HTML report escapes the Suppressed list;
- the PR summary comment is only ever updated when the bot wrote it;
- the copy-in workflow templates are valid, pin their actions, and never
  put a template expression inside a shell or script body;
- the pre-commit hooks run the installed console script.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
ACTION = REPO / "action.yml"
TEMPLATES = [
    REPO / "integrations" / "github-action.yml",
    REPO / "integrations" / "github-action-bot.yml",
]


def _steps(doc: dict) -> list[dict]:
    if "runs" in doc:
        return doc["runs"]["steps"]
    return [s for job in doc["jobs"].values() for s in job["steps"]]


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


def test_html_suppressed_list_is_escaped() -> None:
    """The suppressed list used to be the one `to_html` section that
    skipped `_h()`. The reason comes from `.tf-analyze-ignore.yaml` and the
    file name from the PR, so both are attacker-controlled."""
    from _output import to_html  # type: ignore

    suppressed = [
        {
            "id": "SEC-AWS-SG-001<b>",
            "file": "<svg onload=alert(1)>.tf",
            "line": 3,
            "suppression_reason": "<img src=x onerror=alert(document.domain)>",
        }
    ]
    out = to_html([], [], suppressed)
    assert "<img src=x" not in out
    assert "<svg onload" not in out
    assert "SEC-AWS-SG-001<b>" not in out
    assert "&lt;img src=x onerror=alert(document.domain)&gt;" in out
    assert "&lt;svg onload=alert(1)&gt;.tf:3" in out


# ---------------------------------------------------------------------------
# PR summary comment upsert
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [ACTION, TEMPLATES[0]], ids=lambda p: p.name)
def test_summary_comment_upsert_checks_author(path: Path) -> None:
    """Anyone can post a comment starting `## tf-analyze:`. Matching on the
    prefix alone let a PR author's comment receive every later summary."""
    text = path.read_text()
    assert "github.paginate(github.rest.issues.listComments" in text
    assert "c.user.login === 'github-actions[bot]'" in text
    assert "comments.data.find" not in text


# ---------------------------------------------------------------------------
# Workflow templates and the composite action
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [ACTION, *TEMPLATES], ids=lambda p: p.name)
def test_no_template_expressions_in_shell_or_script(path: Path) -> None:
    """`${{ }}` is substituted into the script text before the shell or
    JavaScript runs, so an input value becomes code. Values go through
    `env:` instead. `github.workspace` is set by the runner and is allowed."""
    for step in _steps(yaml.safe_load(path.read_text())):
        body = step.get("run", "") + str((step.get("with") or {}).get("script", ""))
        exprs = re.findall(r"\$\{\{\s*(.*?)\s*\}\}", body)
        bad = [e for e in exprs if e != "github.workspace"]
        assert not bad, f"{path.name} step {step.get('name')!r} interpolates {bad}"


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_template_actions_are_pinned_to_a_sha(path: Path) -> None:
    for step in _steps(yaml.safe_load(path.read_text())):
        uses = step.get("uses")
        if uses:
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", uses), (
                f"{path.name}: {uses} is not pinned to a commit SHA"
            )


@pytest.mark.parametrize("path", TEMPLATES, ids=lambda p: p.name)
def test_template_engine_ref_defaults_to_a_release(path: Path) -> None:
    """Cloning a moving `main` runs whatever was last pushed, with the
    consumer's token."""
    text = path.read_text()
    assert "|| 'main'" not in text
    assert re.search(r"\|\| 'v\d+\.\d+\.\d+'", text)


def test_template_has_no_top_level_inputs() -> None:
    """GitHub rejects a workflow with a top-level `inputs:` key."""
    assert "inputs" not in yaml.safe_load(TEMPLATES[0].read_text())


def test_template_gate_survives_tee() -> None:
    """The threshold check pipes into `tee`; without pipefail the step's
    exit code is tee's, and the gate never fails."""
    text = TEMPLATES[0].read_text()
    assert "set -o pipefail" in text
    assert "rank.get('${FAIL_ON}'" not in text


def test_bot_never_deletes_or_stages_unrelated_files() -> None:
    """`find . -name '*.bak' -delete` + `git add -A` deleted and committed
    the repo's own tracked .bak files, plus any stray untracked file."""
    text = TEMPLATES[1].read_text()
    assert "find . -name '*.bak' -delete" not in text
    assert "git add -A" not in text
    assert "git add -u" in text
    assert "--others --exclude-standard -- '*.bak'" in text
    # v0.2.6 predates the vendored parser, so the bot installs it; the job
    # holds a write token, so only hash-pinned wheels.
    assert "pip install --require-hashes --only-binary=:all:" in text
    assert "python-hcl2==7.2.1 --hash=sha256:" in text
    assert "lark==1.3.1 --hash=sha256:" in text


# ---------------------------------------------------------------------------
# pre-commit hooks
# ---------------------------------------------------------------------------


def test_pre_commit_hooks_run_the_console_script() -> None:
    """`python3 scripts/detect.py` resolves against the consumer's repo,
    where there is no such file. pre-commit installs this package into
    the hook's venv, so the console script is on PATH."""
    hooks = yaml.safe_load((REPO / ".pre-commit-hooks.yaml").read_text())
    # tomllib is 3.11+; the matrix still runs 3.10.
    pyproject = (REPO / "pyproject.toml").read_text()
    scripts = re.search(r"^\[project\.scripts\]\n(.*?)(?:^\[|\Z)", pyproject, re.M | re.S)
    scripts = set(re.findall(r'^([\w-]+)\s*=', scripts.group(1), re.M))
    assert hooks
    for hook in hooks:
        assert hook["language"] == "python"
        assert hook["entry"] in scripts, hook["id"]
