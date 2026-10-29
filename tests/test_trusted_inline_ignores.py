"""`--inline-ignores-from REF`: a pull request cannot silence its own findings.

Without it, a PR adding `# tf-analyze:ignore SEC-AWS-SG-001` above the
resource it opens to the world passes a `--fail-on CRITICAL` gate. With it,
an inline ignore counts only if the file at the trusted ref (the base
branch) has the same ignore on the same code. These tests build a real git
repo: the base commit is `main`, the working tree is the PR.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from _baseline import InlineMarker as M
from _baseline import inline_ignore_markers, trusted_inline_markers
from _hcl import comments_only
from detect import INLINE_IGNORE_RE

RULE = "SEC-AWS-SG-001"


def _sg(name: str, ignore: str = "") -> str:
    """A security group open to the world on SSH; `ignore` is placed per
    its value: "above" the resource line, or "trailing" on it."""
    marker = f"# tf-analyze:ignore {RULE}"
    head = f'resource "aws_security_group" "{name}" {{'
    if ignore == "above":
        head = f"{marker}\n{head}"
    elif ignore == "trailing":
        head = f"{head} {marker}"
    return f"""{head}
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
"""


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path, base: dict[str, str], pr: dict[str, str]) -> Path:
    """`main` holds `base`; the working tree then holds `pr` on top."""
    repo = tmp_path / "ws"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    for rel, text in base.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo, "checkout", "-q", "-b", "pr")
    for rel, text in pr.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    return repo


def _scan(
    repo: Path, *extra: str, ref: str | None = "main"
) -> tuple[subprocess.CompletedProcess, dict]:
    args = [
        sys.executable,
        str(DETECT),
        "--target",
        str(repo),
        "--format",
        "json",
        "--no-project-config",
        *extra,
    ]
    if ref is not None:
        # `=` form: a ref that looks like an option still reaches the flag.
        args += [f"--inline-ignores-from={ref}"]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    assert proc.returncode in (0, 1), proc.stderr
    return proc, json.loads(proc.stdout)


def _count(report: dict, rule: str = RULE) -> int:
    return sum(1 for f in report["findings"] if f["id"] == rule)


# ---- (a) an ignore already on the base branch is honoured ----------------------


def test_ignore_on_base_unchanged_is_honoured(tmp_path: Path) -> None:
    tf = _sg("open", "above")
    repo = _repo(tmp_path, {"main.tf": tf}, {})
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    assert _count(report) == 0
    assert proc.returncode == 0, proc.stderr
    assert report["summary"]["inline_ignores_from"] == "main"
    assert "inline_ignores_untrusted" not in report["summary"]
    assert "inline_ignores_dropped" not in report["summary"]


# ---- (b) an ignore the PR adds is not honoured ---------------------------------


def test_ignore_added_in_pr_is_not_honoured(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main.tf": _sg("open")}, {"main.tf": _sg("open", "above")})
    # Sanity: without the flag the PR's own comment silences the gate.
    proc, report = _scan(repo, "--fail-on", "CRITICAL", ref=None)
    assert _count(report) == 0 and proc.returncode == 0
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    assert _count(report) == 1
    assert proc.returncode == 1
    assert "1 inline ignore(s) not honoured" in proc.stderr
    dropped = report["summary"]["inline_ignores_dropped"]
    assert [(Path(d["file"]).name, d["line"], d["id"]) for d in dropped] == [
        ("main.tf", 1, RULE)
    ]


# ---- (c) unrelated lines moving the code don't break the match -----------------


def test_ignore_on_base_survives_code_shifting_down(tmp_path: Path) -> None:
    tf = _sg("open", "above")
    shifted = 'variable "a" {}\n\nvariable "b" {}\n\n# a note\n\n' + tf
    repo = _repo(tmp_path, {"main.tf": tf}, {"main.tf": shifted})
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    assert _count(report) == 0, report["findings"]
    assert proc.returncode == 0


# ---- (d) copying an accepted ignore onto identical code is count-aware ---------


def test_marker_copied_onto_identical_code_honoured_once(tmp_path: Path) -> None:
    # Resource lines differ by name, so anchors collide on identical
    # *attribute* lines, where some rules report (SEC-SECRETS-001 reports
    # the `password` line). The base accepts one ignore on such a line; the
    # PR copies it onto a second, identical one in another resource.
    secret = "SEC-SECRETS-001"

    def db(name: str, ignored: bool) -> str:
        mark = f"  # tf-analyze:ignore {secret}\n" if ignored else ""
        return (
            f'resource "aws_db_instance" "{name}" {{\n'
            '  engine            = "mysql"\n'
            '  instance_class    = "db.t3.micro"\n'
            '  username          = "admin"\n'
            f"{mark}"
            '  password          = "SuperSecret123!"\n'
            "  storage_encrypted = true\n"
            "}\n"
        )

    base = db("a", True) + db("b", False)
    pr = db("a", True) + db("b", True)
    repo = _repo(tmp_path, {"main.tf": base}, {"main.tf": pr})
    # Sanity: without the flag both copies suppress.
    _, unflagged = _scan(repo, ref=None)
    assert _count(unflagged, secret) == 0
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    # The base vouches for one such ignore, so only one is honoured.
    assert [f["resource"] for f in report["findings"] if f["id"] == secret] == [
        "aws_db_instance.b"
    ]
    assert proc.returncode == 1
    assert len(report["summary"]["inline_ignores_dropped"]) == 1


def test_anchor_matching_is_count_aware_unit() -> None:
    base = [M(1, RULE, "x = 1", True)]
    head = [
        M(1, RULE, "x = 1", True),
        M(5, RULE, "x = 1", True),
        M(9, "OTHER", "x = 1", False),
    ]
    trusted, dropped = trusted_inline_markers(head, base)
    assert trusted == [M(1, RULE, "x = 1", True)]
    assert dropped == [M(5, RULE, "x = 1", True), M(9, "OTHER", "x = 1", False)]


# ---- (e) a file new in the PR honours no inline ignores ------------------------


def test_new_file_in_pr_honours_no_ignores(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path, {"other.tf": 'variable "x" {}\n'}, {"main.tf": _sg("open", "above")}
    )
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    assert _count(report) == 1
    assert proc.returncode == 1
    assert len(report["summary"]["inline_ignores_dropped"]) == 1


# ---- (f) a ref that can't be read honours none (fail closed) -------------------


def test_unknown_ref_honours_no_ignores(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main.tf": _sg("open", "above")}, {})
    proc, report = _scan(repo, "--fail-on", "CRITICAL", ref="refs/heads/nope")
    assert _count(report) == 1
    assert proc.returncode == 1
    assert (
        proc.stderr.count(
            "WARN: cannot read --inline-ignores-from ref 'refs/heads/nope'"
        )
        == 1
    )
    assert report["summary"]["inline_ignores_untrusted"] is True
    assert report["summary"]["inline_ignores_from"] == "refs/heads/nope"


def test_not_a_work_tree_honours_no_ignores(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    (target / "main.tf").write_text(_sg("open", "above"))
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(tmp_path)}
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--format",
            "json",
            "--no-project-config",
            "--inline-ignores-from",
            "main",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    report = json.loads(proc.stdout)
    assert _count(report) == 1
    assert report["summary"]["inline_ignores_untrusted"] is True
    assert "WARN: cannot read --inline-ignores-from ref 'main'" in proc.stderr


def test_ref_that_looks_like_an_option_is_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main.tf": _sg("open", "above")}, {})
    proc, report = _scan(repo, ref="--output=/tmp/x")
    assert _count(report) == 1
    assert report["summary"]["inline_ignores_untrusted"] is True


def test_git_missing_honours_no_ignores(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main.tf": _sg("open", "above")}, {})
    env = {**os.environ, "PATH": str(tmp_path / "empty-bin")}
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(repo),
            "--format",
            "json",
            "--no-project-config",
            "--inline-ignores-from",
            "main",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode in (0, 1), proc.stderr
    report = json.loads(proc.stdout)
    assert _count(report) == 1
    assert report["summary"]["inline_ignores_untrusted"] is True


# ---- (g) trailing vs standalone comment anchors --------------------------------


def _markers(text: str) -> list[tuple[int, str, str]]:
    return inline_ignore_markers(
        text, comments_only(text), inline_ignore_re=INLINE_IGNORE_RE
    )


def test_trailing_comment_anchors_its_own_line() -> None:
    text = 'resource "a" "b" {   # tf-analyze:ignore X-1\n  k = 1\n}\n'
    assert _markers(text) == [(1, "X-1", 'resource "a" "b" {', False)]


def test_double_slash_marker_is_one() -> None:
    text = '// tf-analyze:ignore X-1\nresource "a" "b" {\n}\n'
    assert _markers(text) == [(1, "X-1", 'resource "a" "b" {', True)]


@pytest.mark.parametrize(
    "text",
    [
        '# tf-analyze:ignore X-1\nresource "a" "b" {\n  k = 1 # tf-analyze:ignore X-2\n  j = 2\n}\n',
        '/* c */ # tf-analyze:ignore X-1\nresource "a" "b" {\n}\n',
        'x = "# tf-analyze:ignore X-1"\ny = 1 // tf-analyze:ignore X-3\nz = 2\n',
    ],
)
def test_trusted_path_has_the_same_reach_as_the_default(text: str) -> None:
    # Trusting every marker must give exactly what the untrusted path gives:
    # a trailing comment covers its own line only, a standalone one the next
    # line too, and a marker in a string counts for nothing.
    from _baseline import markers_to_suppressions
    from detect import load_inline_suppressions

    markers = _markers(text)
    trusted, dropped = trusted_inline_markers(markers, markers)
    assert dropped == []
    assert markers_to_suppressions(trusted) == load_inline_suppressions(text)


def test_trusted_trailing_ignore_does_not_reach_the_next_line(tmp_path: Path) -> None:
    secret = "SEC-SECRETS-001"
    tf = (
        'resource "aws_db_instance" "a" {\n'
        '  engine            = "mysql" # tf-analyze:ignore SEC-SECRETS-001\n'
        '  password          = "SuperSecret123!"\n'
        "}\n"
    )
    repo = _repo(tmp_path, {"main.tf": tf}, {})
    _, report = _scan(repo)
    assert _count(report, secret) == 1


def test_standalone_comment_anchors_next_code_line() -> None:
    text = '# tf-analyze:ignore X-1\n\n# why: legacy\n/* more */\n  resource   "a"  "b" {\n}\n'
    assert _markers(text) == [(1, "X-1", 'resource "a" "b" {', True)]


def test_marker_in_a_string_or_heredoc_is_not_one() -> None:
    text = (
        'resource "a" "b" {\n'
        '  description = "# tf-analyze:ignore X-1"\n'
        "  script = <<EOT\n"
        "# tf-analyze:ignore X-2\n"
        "EOT\n"
        "}\n"
    )
    assert _markers(text) == []


def test_trailing_and_standalone_on_the_same_code_are_different(tmp_path: Path) -> None:
    # The base accepted a trailing ignore; the PR moves it above the line.
    # Same rule, same code: the anchor is the code, so it still matches.
    repo = _repo(
        tmp_path,
        {"main.tf": _sg("open", "trailing")},
        {"main.tf": _sg("open", "above")},
    )
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    assert _count(report) == 0
    assert proc.returncode == 0


def test_ignore_moved_onto_other_code_is_not_honoured(tmp_path: Path) -> None:
    # The base ignores the rule on resource "a"; the PR moves the comment
    # onto a new resource "b". The anchor (the code) differs.
    repo = _repo(
        tmp_path,
        {"main.tf": _sg("a", "above")},
        {"main.tf": _sg("a") + "\n" + _sg("b", "above")},
    )
    proc, report = _scan(repo, "--fail-on", "CRITICAL")
    assert sorted(f["resource"] for f in report["findings"] if f["id"] == RULE) == [
        "aws_security_group.a",
        "aws_security_group.b",
    ]
    assert proc.returncode == 1


def test_no_suppress_ignores_the_flag(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main.tf": _sg("open", "above")}, {})
    _, report = _scan(repo, "--no-suppress", ref="refs/heads/nope")
    assert _count(report) == 1
    assert "inline_ignores_from" not in report["summary"]


@pytest.mark.parametrize("sub", ["", "infra/"])
def test_target_subfolder_reads_paths_from_the_work_tree_root(
    tmp_path: Path, sub: str
) -> None:
    repo = _repo(tmp_path, {f"{sub}main.tf": _sg("open", "above")}, {})
    proc, report = _scan(repo / sub if sub else repo, "--fail-on", "CRITICAL")
    assert _count(report) == 0
    assert proc.returncode == 0


# ---- the GitHub Action passes the flag on PRs only ------------------------------

yaml = pytest.importorskip("yaml")

ACTION = yaml.safe_load((REPO_ROOT / "action.yml").read_text())
# How GitHub runs a composite step with `shell: bash`.
GH_BASH = ("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c")
TRUSTED_STEP = "Use the base branch's tf-analyze config"


def _step(name: str) -> dict:
    return next(s for s in ACTION["runs"]["steps"] if s.get("name") == name)


def _args_step(tmp_path: Path, **env: str) -> list[str]:
    args_file = tmp_path / "base-args"
    script = _step("Build detect.py args")["run"].replace(
        "/tmp/tf-analyze-base-args", str(args_file)
    )
    full = {
        **os.environ,
        "TFA_TARGET": ".",
        "TFA_MODE_OUT": "static",
        "GITHUB_OUTPUT": str(tmp_path / "o"),
        "TFA_TRUSTED_DIR": "",
        "TFA_TRUSTED_CONFIG": "",
        "TFA_TRUSTED_IGNORE": "",
        "TFA_TRUSTED_BASELINE": "",
        "TFA_TRUSTED_INLINE_REF": "",
        **env,
    }
    subprocess.run([*GH_BASH, script], env=full, check=True, capture_output=True)
    return args_file.read_text().splitlines()


def _run_trusted_step(
    repo: Path, tmp_path: Path, base_ref: str = "main"
) -> dict[str, str]:
    out = tmp_path / "gh_output"
    out.write_text("")
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir(exist_ok=True)
    proc = subprocess.run(
        [*GH_BASH, _step(TRUSTED_STEP)["run"]],
        env={
            **os.environ,
            "TFA_TARGET": ".",
            "TFA_BASELINE": "",
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


def _pr_repo_with_origin(
    tmp_path: Path, base: dict[str, str], pr: dict[str, str]
) -> Path:
    """`_repo`, plus an `origin` the action's step fetches the base from."""
    repo = _repo(tmp_path, base, pr)
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")
    return repo


def test_trusted_step_runs_only_on_prs_without_trust_pr_config() -> None:
    cond = _step(TRUSTED_STEP)["if"]
    assert "github.event_name == 'pull_request'" in cond
    assert "github.event_name == 'merge_group'" in cond
    assert "inputs.trust-pr-config != 'true'" in cond
    env = _step("Build detect.py args")["env"]
    assert env["TFA_TRUSTED_INLINE_REF"] == "${{ steps.trusted.outputs.inline-ref }}"


def test_args_step_passes_the_flag_on_a_pr(tmp_path: Path) -> None:
    args = _args_step(
        tmp_path,
        TFA_TRUSTED_DIR=str(tmp_path),
        TFA_TRUSTED_IGNORE="/trusted/none",
        TFA_TRUSTED_INLINE_REF="refs/tf-analyze/base",
    )
    i = args.index("--inline-ignores-from")
    assert args[i + 1] == "refs/tf-analyze/base"


def test_args_step_omits_the_flag_on_push_or_with_trust_pr_config(
    tmp_path: Path,
) -> None:
    # On push, and with trust-pr-config: true, the trusted step is skipped,
    # so none of its outputs are set.
    assert "--inline-ignores-from" not in _args_step(tmp_path)


def test_trusted_step_ref_resolves_and_gates_a_pr_added_ignore(tmp_path: Path) -> None:
    repo = _pr_repo_with_origin(
        tmp_path,
        {"main.tf": _sg("kept", "above") + "\n" + _sg("open")},
        {"main.tf": _sg("kept", "above") + "\n" + _sg("open", "above")},
    )
    outputs = _run_trusted_step(repo, tmp_path)
    assert outputs["inline-ref"] == "refs/tf-analyze/base"
    proc, report = _scan(repo, "--fail-on", "CRITICAL", ref=outputs["inline-ref"])
    assert [f["resource"] for f in report["findings"] if f["id"] == RULE] == [
        "aws_security_group.open"
    ]
    assert proc.returncode == 1


def test_trusted_step_unreadable_base_fails_closed(tmp_path: Path) -> None:
    repo = _pr_repo_with_origin(tmp_path, {"main.tf": _sg("open", "above")}, {})
    # A stale copy left by an earlier run must not stand in for the fetch.
    _git(repo, "update-ref", "refs/tf-analyze/base", "HEAD")
    outputs = _run_trusted_step(repo, tmp_path, base_ref="no-such-branch")
    assert outputs["inline-ref"] == "refs/tf-analyze/base"
    proc, report = _scan(repo, "--fail-on", "CRITICAL", ref=outputs["inline-ref"])
    assert _count(report) == 1
    assert report["summary"]["inline_ignores_untrusted"] is True
    assert proc.returncode == 1


def test_scan_step_marks_the_workspace_safe_for_git(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker-args"
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" >> "{log}"\n'
        'echo \'{"summary": {}, "findings": []}\'\n'
    )
    docker.chmod(0o755)
    args_file = tmp_path / "base-args"
    args_file.write_text(
        "--target\n/workspace/.\n--inline-ignores-from\nrefs/tf-analyze/base\n"
    )
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_output"
    gh_out.write_text("")
    script = (
        _step("Run tf-analyze (JSON)")["run"]
        .replace("${{ github.workspace }}", str(ws))
        .replace("/tmp/tf-analyze-base-args", str(args_file))
    )
    proc = subprocess.run(
        [*GH_BASH, script],
        cwd=ws,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "TFA_IMAGE": "img",
            "TFA_TRUSTED_DIR": "",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(gh_out),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    first_run = log.read_text().split("--cache-file")[0].splitlines()
    for kv in (
        "GIT_CONFIG_COUNT=1",
        "GIT_CONFIG_KEY_0=safe.directory",
        "GIT_CONFIG_VALUE_0=/workspace",
    ):
        i = first_run.index(kv)
        assert first_run[i - 1] == "-e"
    # The env flags go to docker, before the image name.
    assert first_run.index("GIT_CONFIG_COUNT=1") < first_run.index("img")


def test_scan_step_surfaces_untrusted_and_dropped_counts(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    report = {
        "summary": {
            "inline_ignores_from": "refs/tf-analyze/base",
            "inline_ignores_untrusted": True,
            "inline_ignores_dropped": [
                {"file": "x\n::error::forged", "line": 1, "id": RULE}
            ],
        },
        "findings": [],
    }
    docker = bin_dir / "docker"
    docker.write_text("#!/bin/sh\ncat <<'EOF'\n" + json.dumps(report) + "\nEOF\n")
    docker.chmod(0o755)
    args_file = tmp_path / "base-args"
    args_file.write_text("--target\n/workspace/.\n")
    runner_temp = tmp_path / "rt"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_output"
    gh_out.write_text("")
    script = (
        _step("Run tf-analyze (JSON)")["run"]
        .replace("${{ github.workspace }}", str(ws))
        .replace("/tmp/tf-analyze-base-args", str(args_file))
    )
    proc = subprocess.run(
        [*GH_BASH, script],
        cwd=ws,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "TFA_IMAGE": "img",
            "TFA_TRUSTED_DIR": "",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(gh_out),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "::warning::tf-analyze: could not read the base branch" in proc.stderr
    assert "::notice::tf-analyze: 1 inline tf-analyze:ignore comment(s)" in proc.stderr
    assert "forged" not in proc.stderr


def test_integration_workflow_passes_the_flag_on_prs_only() -> None:
    wf = yaml.safe_load((REPO_ROOT / "integrations" / "github-action.yml").read_text())
    steps = wf["jobs"]["analyze"]["steps"]
    trusted = next(s for s in steps if s.get("name") == TRUSTED_STEP)
    assert 'git update-ref -d "$BASE"' in trusted["run"]
    run = next(s for s in steps if s.get("name") == "Run tf-analyze")["run"]
    flag = run.index("EXTRA_ARGS+=(--inline-ignores-from refs/tf-analyze/base)")
    # The nearest enclosing condition is the pull_request check.
    cond = run.rindex("if [", 0, flag)
    assert run[cond:].startswith('if [ "$TFA_EVENT" = "pull_request" ]')
    # Not via `${{ }}` in the script.
    assert "${{" not in run
    # git is pinned to the checkout's own repository.
    assert (
        'export GIT_DIR="$GITHUB_WORKSPACE/.git" GIT_WORK_TREE="$GITHUB_WORKSPACE"'
        in run
    )


def test_scan_step_pins_the_repository() -> None:
    run = _step("Run tf-analyze (JSON)")["run"]
    assert "-e GIT_DIR=/workspace/.git -e GIT_WORK_TREE=/workspace" in run


# ---- a bare repository planted in the target is never used ---------------------


def _planted(tmp_path: Path, *, pr_tf: str, planted_tf: str) -> tuple[Path, Path, Path]:
    """A real repo whose `main` has `infra/main.tf` with no ignore, and a
    PR working tree whose `infra/` holds `pr_tf` plus a *bare* repository
    (HEAD, config, objects, refs: no `.git` path, so a PR can commit it).
    The planted repo's `main` has `planted_tf` as `main.tf`, its work tree
    is `infra/`, and its config runs a command through core.fsmonitor.
    Returns (repo, infra, marker file the command would create)."""
    repo = _repo(tmp_path, {"infra/main.tf": _sg("open")}, {"infra/main.tf": pr_tf})
    infra = repo / "infra"
    evil = tmp_path / "evil"
    evil.mkdir()
    _git(evil, "init", "-q", "-b", "main")
    (evil / "main.tf").write_text(planted_tf)
    _git(evil, "add", "-A")
    _git(evil, "-c", "user.email=e@e", "-c", "user.name=e", "commit", "-q", "-m", "x")
    bare = tmp_path / "evil.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(evil), str(bare)], check=True)
    for item in bare.iterdir():
        dest = infra / item.name
        if item.is_dir():
            import shutil

            shutil.copytree(item, dest)
        else:
            dest.write_bytes(item.read_bytes())
    marker = tmp_path / "PWNED"
    cfg = infra / "config"
    for key, value in (
        ("core.bare", "false"),
        ("core.worktree", str(infra)),
        ("core.fsmonitor", f"touch '{marker}'; false"),
    ):
        subprocess.run(["git", "config", "--file", str(cfg), key, value], check=True)
    # Sanity: plain git, run in the target, uses the planted repo and runs
    # its command.
    found = subprocess.run(
        ["git", "rev-parse", "--show-toplevel", "--absolute-git-dir"],
        cwd=infra,
        capture_output=True,
        text=True,
        check=True,
    )
    assert [Path(x).resolve() for x in found.stdout.split()] == [infra.resolve()] * 2
    subprocess.run(
        ["git", "status", "--short"], cwd=infra, capture_output=True, check=False
    )
    assert marker.exists()
    marker.unlink()
    return repo, infra, marker


def test_planted_bare_repo_is_not_a_trusted_base(tmp_path: Path) -> None:
    repo, infra, marker = _planted(
        tmp_path, pr_tf=_sg("open", "above"), planted_tf=_sg("open", "above")
    )
    proc, report = _scan(infra, "--fail-on", "CRITICAL")
    assert _count(report) == 1
    assert proc.returncode == 1
    assert report["summary"]["inline_ignores_untrusted"] is True
    assert not marker.exists()


def test_planted_bare_repo_does_not_scope_diff_mode(tmp_path: Path) -> None:
    # The planted repo's `main` equals the PR's file, so a diff against it
    # would say nothing changed and scan nothing.
    repo, infra, marker = _planted(tmp_path, pr_tf=_sg("open"), planted_tf=_sg("open"))
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(infra),
            "--format",
            "json",
            "--no-project-config",
            "--mode",
            "diff",
            "--diff-base",
            "main",
            "--fail-on",
            "CRITICAL",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(proc.stdout)
    assert _count(report) == 1
    assert proc.returncode == 1
    assert "scanning all files" in proc.stderr
    assert not marker.exists()


def test_pinned_repository_is_used_and_planted_one_ignored(tmp_path: Path) -> None:
    # The real base has the ignore; the planted repo is bypassed by the pin.
    repo, infra, marker = _planted(
        tmp_path, pr_tf=_sg("open", "above"), planted_tf=_sg("open", "above")
    )
    _git(repo, "checkout", "-q", "main")
    (infra / "main.tf").write_text(_sg("open", "above"))
    _git(repo, "add", "infra/main.tf")
    _git(
        repo,
        "-c",
        "user.email=e@e",
        "-c",
        "user.name=e",
        "commit",
        "-q",
        "-m",
        "accept",
    )
    env = {**os.environ, "GIT_DIR": str(repo / ".git"), "GIT_WORK_TREE": str(repo)}
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(infra),
            "--format",
            "json",
            "--no-project-config",
            "--inline-ignores-from=main",
            "--fail-on",
            "CRITICAL",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    report = json.loads(proc.stdout)
    assert _count(report) == 0, proc.stderr
    assert proc.returncode == 0
    assert "inline_ignores_untrusted" not in report["summary"]
    assert not marker.exists()


def test_a_pin_git_disagrees_with_fails_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"main.tf": _sg("open", "above")}, {})
    env = {
        **os.environ,
        "GIT_DIR": str(tmp_path / "missing" / ".git"),
        "GIT_WORK_TREE": str(repo),
    }
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(repo),
            "--format",
            "json",
            "--no-project-config",
            "--inline-ignores-from=main",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    report = json.loads(proc.stdout)
    assert _count(report) == 1
    assert report["summary"]["inline_ignores_untrusted"] is True


def test_verified_work_tree_rejects_a_foreign_git_dir(
    tmp_path: Path, monkeypatch
) -> None:
    from _diff import verified_work_tree

    repo = _repo(tmp_path, {"main.tf": "\n"}, {})
    monkeypatch.delenv("GIT_DIR", raising=False)
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    root, err = verified_work_tree(repo)
    assert root == repo.resolve() and err is None
    # A pin naming another work tree than the one git reports.
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(repo))
    root, err = verified_work_tree(repo)
    assert root == repo.resolve()
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    root, err = verified_work_tree(repo)
    assert root is None and err
