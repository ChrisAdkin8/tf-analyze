"""Three gate bypasses in what a scan reads.

* `--mode diff` never scanned a changed `.tfvars` or workflow file, so a
  secret added to `prod.auto.tfvars` passed the gate.
* A changed path with a non-ASCII byte came out of git quoted
  (`"caf\\303\\251/main.tf"`), named no file and was dropped.
* A module in `.terraform/` was never scanned, even when a local `source`
  called it and real Terraform loaded it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _diff
import _modes
import _tfjson
import changelog
import pytest

REPO = Path(__file__).resolve().parents[1]

SG = (
    'resource "aws_security_group" "open" {\n'
    '  name = "open"\n'
    "  ingress {\n"
    "    from_port   = 22\n"
    "    to_port     = 22\n"
    '    protocol    = "tcp"\n'
    '    cidr_blocks = ["0.0.0.0/0"]\n'
    "  }\n"
    "}\n"
)
SG_RULE = "SEC-AWS-SG-001"
SECRET_RULE = "SEC-SECRETS-001"
PASSWORD_VAR = 'variable "db_password" {}\n'
SECRET = 'db_password = "SuperSecret123!"\n'
CALL_NET = 'module "net" {\n  source = "./.terraform/m"\n}\n'
WORKFLOW = "on: push\npermissions: write-all\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=str(repo), check=True, capture_output=True, text=True
    )


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)


def _repo(root: Path, files: dict[str, str]) -> Path:
    """A repo with `files` on `main`, on a new branch `pr`."""
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _write(root, files)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base", "--allow-empty")
    _git(root, "switch", "-q", "-c", "pr")
    return root


def _commit(repo: Path, files: dict[str, str]) -> None:
    _write(repo, files)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")


def _scan(target: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--fail-on",
            "HIGH",
            "--format",
            "json",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _diff_scan(target: Path, *extra: str) -> subprocess.CompletedProcess:
    return _scan(target, "--mode", "diff", "--diff-base", "main", *extra)


def _hits(proc: subprocess.CompletedProcess, rule: str) -> list[str]:
    """The files `rule` fired on."""
    findings = json.loads(proc.stdout)["findings"]
    return [f["file"] for f in findings if f["id"] == rule]


# ---- (a) changed .tfvars and other extra files in diff mode -----------------


def test_diff_scans_a_changed_tfvars(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"variables.tf": PASSWORD_VAR})
    _commit(repo, {"prod.auto.tfvars": SECRET})
    proc = _diff_scan(repo)
    assert proc.returncode == 1, proc.stderr
    assert [Path(f).name for f in _hits(proc, SECRET_RULE)] == ["prod.auto.tfvars"]


def test_diff_scans_an_untracked_tfvars(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"variables.tf": PASSWORD_VAR})
    _write(repo, {"prod.auto.tfvars": SECRET})
    assert _diff_scan(repo).returncode == 1


def test_diff_scans_a_tfvars_in_a_folder_with_no_tf_files(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"variables.tf": PASSWORD_VAR})
    _commit(repo, {"env/prod/app.tfvars": SECRET})
    assert _hits(_diff_scan(repo), SECRET_RULE)


def test_diff_leaves_out_an_unchanged_tfvars(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "variables.tf": PASSWORD_VAR,
            "other/old.tfvars": SECRET,
            "main.tf": "locals {}\n",
        },
    )
    _commit(repo, {"new.tf": "locals {}\n", "b.auto.tfvars": 'db_password = "x"\n'})
    assert not _hits(_diff_scan(repo), SECRET_RULE)
    assert _hits(_scan(repo), SECRET_RULE)  # a full scan does see it


def test_diff_honours_ignore_paths_for_a_changed_tfvars(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "variables.tf": PASSWORD_VAR,
            ".tf-analyze.yaml": "ignore_paths:\n  - examples/\n",
        },
    )
    _commit(repo, {"examples/demo.tfvars": SECRET})
    assert not _hits(_diff_scan(repo), SECRET_RULE)


def test_diff_scans_a_changed_workflow_file(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    _commit(repo, {".github/workflows/ci.yml": WORKFLOW})
    full = {f["id"] for f in json.loads(_scan(repo).stdout)["findings"]}
    cicd = {r for r in full if r.startswith("SEC-CICD")}
    assert cicd, "fixture no longer trips a SEC-CICD rule"
    got = {f["id"] for f in json.loads(_diff_scan(repo).stdout)["findings"]}
    assert cicd <= got


def test_diff_with_a_subfolder_target_scans_only_changes_under_it(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {"infra/variables.tf": PASSWORD_VAR, "other/x.tf": "locals {}\n"},
    )
    _commit(repo, {"infra/a.tfvars": SECRET, "other/b.tfvars": SECRET})
    files = _diff.get_diff_files(repo / "infra", "main")
    assert (repo / "infra" / "a.tfvars").resolve() in files
    assert (repo / "other" / "b.tfvars").resolve() not in files
    hits = _hits(_diff_scan(repo / "infra"), SECRET_RULE)
    assert [Path(f).name for f in hits] == ["a.tfvars"]


def test_a_deleted_tfvars_still_rescans_its_module_without_crashing(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": SG, "x.tfvars": "a = 1\n"})
    (repo / "x.tfvars").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "pr")
    assert _hits(_diff_scan(repo), SG_RULE)


def test_a_change_to_no_terraform_file_is_still_reported_as_such(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": SG})
    _commit(repo, {"README.md": "hello\n"})
    proc = _diff_scan(repo)
    assert proc.returncode == 0, proc.stderr
    assert "no changed .tf / .tf.json files in diff" in proc.stderr
    assert not _hits(proc, SG_RULE)


def test_a_changed_non_terraform_file_widens_nothing(tmp_path) -> None:
    # Not read for `variable`, and its folder isn't pulled in when deleted.
    repo = _repo(
        tmp_path / "r", {"main.tf": SG, "notes.txt": "x\n", "b/gone.md": "x\n"}
    )
    (repo / "b" / "gone.md").unlink()
    _commit(repo, {"notes.txt": 'variable "a" {}\n'})
    assert not _hits(_diff_scan(repo), SG_RULE)


# ---- (b) paths git would quote ----------------------------------------------


def test_diff_scans_a_non_ascii_folder(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"README.md": "x\n", "main.tf": "locals {}\n"})
    _commit(repo, {"café/main.tf": SG})
    proc = _diff_scan(repo)
    assert proc.returncode == 1, proc.stderr
    assert _hits(proc, SG_RULE)


def test_diff_scans_an_untracked_non_ascii_folder(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    _write(repo, {"日本語/main.tf": SG})
    assert _diff_scan(repo).returncode == 1


def test_diff_scans_a_non_ascii_tfvars(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"variables.tf": PASSWORD_VAR})
    _commit(repo, {"café/prod.tfvars": SECRET})
    assert _hits(_diff_scan(repo), SECRET_RULE)


@pytest.mark.parametrize(
    "folder",
    ['a"b', "new\nline", "tab\there", " leading space", "back\\slash"],
    ids=["quote", "newline", "tab", "space", "backslash"],
)
def test_diff_keeps_paths_git_would_quote(tmp_path, folder) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    _commit(repo, {f"{folder}/main.tf": SG})
    want = (repo / folder / "main.tf").resolve()
    assert want in _diff.get_diff_files(repo, "main")
    _write(repo, {f"{folder}/untracked.tf": SG})
    assert (repo / folder / "untracked.tf").resolve() in _diff.get_diff_files(
        repo, "main"
    )


def test_a_non_ascii_path_survives_the_two_dot_fallback(tmp_path) -> None:
    # No merge base, so the three-dot diff fails and the two-dot one runs.
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    _git(repo, "switch", "-q", "--orphan", "other")
    _commit(repo, {"café/main.tf": SG})
    assert (repo / "café" / "main.tf").resolve() in _diff.get_diff_files(repo, "main")


def test_split_git_paths_keeps_bytes_that_are_not_utf8() -> None:
    raw = b"caf\xe9/main.tf\0a\nb.tf\0"
    names = _diff.split_git_paths(raw)
    assert len(names) == 2 and names[1] == "a\nb.tf"
    assert (
        names[0].encode(sys.getfilesystemencoding(), "surrogateescape")
        == b"caf\xe9/main.tf"
    )
    assert _diff.split_git_paths(b"") == [] and _diff.split_git_paths(None) == []


def test_trend_lists_a_non_ascii_path(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"café/main.tf": "locals {}\n", "b.txt": "x\n"})
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert _modes.trend_tf_files_at_sha(repo, head) == ["café/main.tf"]


def test_changelog_check_sees_a_non_ascii_fragment(tmp_path, monkeypatch) -> None:
    repo = _repo(tmp_path / "r", {"changelog.d/README.md": "x\n"})
    _commit(repo, {"changelog.d/café.md": "## Title\n\n- entry\n"})
    monkeypatch.setattr(changelog, "REPO_ROOT", repo)
    assert changelog.check_branch("main") == []


def test_changelog_check_still_refuses_a_direct_edit(tmp_path, monkeypatch) -> None:
    repo = _repo(tmp_path / "r", {"CHANGELOG.md": "x\n"})
    _commit(repo, {"CHANGELOG.md": "y\n", "changelog.d/a.md": "## T\n\n- e\n"})
    monkeypatch.setattr(changelog, "REPO_ROOT", repo)
    assert "edited directly" in changelog.check_branch("main")[0]


# ---- (c) modules under .terraform -------------------------------------------


def test_a_called_module_in_dot_terraform_is_scanned(tmp_path) -> None:
    _write(tmp_path, {"main.tf": CALL_NET, ".terraform/m/main.tf": SG})
    proc = _scan(tmp_path)
    assert proc.returncode == 1, proc.stderr
    assert _hits(proc, SG_RULE) == [
        str(tmp_path.resolve() / ".terraform" / "m" / "main.tf")
    ]


def test_an_uncalled_module_in_dot_terraform_stays_skipped(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n  version = "5.0.0"\n}\n',
            ".terraform/modules/vpc/main.tf": SG,
            ".terraform/m/main.tf": SG,
        },
    )
    assert not _hits(_scan(tmp_path), SG_RULE)


def test_a_commented_out_call_reaches_nothing(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": '# module "net" {\n#   source = "./.terraform/m"\n# }\nlocals {}\n',
            ".terraform/m/main.tf": SG,
        },
    )
    assert not _hits(_scan(tmp_path), SG_RULE)


def test_dot_terraform_reached_with_dot_dot_and_transitively(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "envs/prod/main.tf": 'module "a" {\n  source = "../../.terraform/a"\n}\n',
            ".terraform/a/main.tf": 'module "b" {\n  source = "../b"\n}\n',
            ".terraform/b/main.tf": 'module "c" {\n  source = "./x/../c"\n}\n',
            ".terraform/b/c/main.tf": SG,
            ".terraform/b/sub-not-called/main.tf": SG,
        },
    )
    hits = _hits(_scan(tmp_path), SG_RULE)
    assert hits == [str(tmp_path.resolve() / ".terraform" / "b" / "c" / "main.tf")]


def test_modules_in_dot_terraform_calling_each_other_end(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "a" {\n  source = "./.terraform/a"\n}\n',
            ".terraform/a/main.tf": 'module "b" {\n  source = "../b"\n}\nmodule "me" {\n  source = "./"\n}\n',
            ".terraform/b/main.tf": 'module "a" {\n  source = "../a"\n}\n' + SG,
        },
    )
    assert len(_hits(_scan(tmp_path), SG_RULE)) == 1


def test_a_source_leaving_the_target_is_not_read(tmp_path, monkeypatch) -> None:
    target = tmp_path / "t"
    _write(
        tmp_path,
        {
            "t/main.tf": 'module "a" {\n  source = "../.terraform/a"\n}\n',
            "t/.terraform/unused/x.tf": "locals {}\n",
            ".terraform/a/main.tf": SG,
        },
    )
    read: list[Path] = []
    real = _diff._tf_text
    monkeypatch.setattr(_diff, "_tf_text", lambda fp: read.append(fp) or real(fp))
    files = _diff.walk_tf_files(target, contain=True)
    assert files == [target / "main.tf"]
    assert not [
        p for p in read if not Path(p).resolve().is_relative_to(target.resolve())
    ]


def test_a_symlink_out_of_dot_terraform_stays_out_of_a_fleet_scan(tmp_path) -> None:
    target = tmp_path / "t"
    _write(
        tmp_path,
        {"t/main.tf": CALL_NET, "outside/main.tf": SG, "t/.terraform/keep": "x"},
    )
    (target / ".terraform" / "m").symlink_to(
        tmp_path / "outside", target_is_directory=True
    )
    proc = _scan(target, "--mode", "fleet")
    assert SG_RULE not in proc.stdout


def test_a_file_symlink_out_of_dot_terraform_is_not_scanned(tmp_path) -> None:
    target = tmp_path / "t"
    _write(
        tmp_path,
        {
            "t/main.tf": CALL_NET,
            "outside.tf": SG,
            "t/.terraform/m/ok.tf": "locals {}\n",
        },
    )
    (target / ".terraform" / "m" / "x.tf").symlink_to(tmp_path / "outside.tf")
    assert not _hits(_scan(target), SG_RULE)


def test_a_fleet_scan_covers_a_called_module_in_dot_terraform(tmp_path) -> None:
    _write(tmp_path, {"main.tf": CALL_NET, ".terraform/m/main.tf": SG})
    assert _scan(tmp_path, "--mode", "fleet").returncode == 1


def test_a_symlink_into_dot_terraform_used_as_a_source_is_scanned(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "m" {\n  source = "./mods/m"\n}\n',
            ".terraform/modules/m/main.tf": SG,
        },
    )
    (tmp_path / "mods").symlink_to(
        tmp_path / ".terraform" / "modules", target_is_directory=True
    )
    assert len(_hits(_scan(tmp_path), SG_RULE)) == 1


def test_a_linked_in_folder_reaches_its_own_dot_terraform(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "shared/main.tf": CALL_NET,
            "shared/.terraform/m/main.tf": SG,
            "app/x.tf": "locals {}\n",
        },
    )
    (repo / "app" / "net").symlink_to(repo / "shared", target_is_directory=True)
    hits = _hits(_scan(repo / "app"), SG_RULE)
    assert hits == [
        str((repo / "app").resolve() / "net" / ".terraform" / "m" / "main.tf")
    ]


def test_a_symlink_loop_as_a_source_does_not_crash(tmp_path) -> None:
    _write(
        tmp_path, {"main.tf": 'module "x" {\n  source = "./.terraform/loop"\n}\n' + SG}
    )
    (tmp_path / ".terraform").mkdir()
    (tmp_path / ".terraform" / "loop").symlink_to(tmp_path / ".terraform" / "loop")
    proc = _scan(tmp_path)
    assert proc.returncode == 1, proc.stderr
    assert len(_hits(proc, SG_RULE)) == 1


def test_ignore_paths_still_cover_dot_terraform(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": CALL_NET,
            ".terraform/m/main.tf": SG,
            ".tf-analyze.yaml": "ignore_paths:\n  - .terraform/m\n",
        },
    )
    assert not _hits(_scan(tmp_path), SG_RULE)


def test_an_ignored_caller_reaches_nothing(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": "locals {}\n",
            "examples/main.tf": 'module "n" {\n  source = "../.terraform/m"\n}\n',
            ".terraform/m/main.tf": SG,
            ".tf-analyze.yaml": "ignore_paths:\n  - examples/\n",
        },
    )
    assert not _hits(_scan(tmp_path), SG_RULE)


def test_a_tf_json_caller_reaches_dot_terraform(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf.json": json.dumps(
                {"module": {"net": {"source": "./.terraform/m"}}}
            ),
            ".terraform/m/main.tf": SG,
        },
    )
    assert _hits(_scan(tmp_path), SG_RULE)


def test_the_walk_is_unchanged_without_a_dot_terraform_folder(
    tmp_path, monkeypatch
) -> None:
    _write(tmp_path, {"main.tf": CALL_NET})
    monkeypatch.setattr(
        _diff, "_tf_text", lambda fp: pytest.fail("read a file for nothing")
    )
    assert _diff.walk_tf_files(tmp_path) == [tmp_path / "main.tf"]


def test_tf_source_files_alone_still_skips_dot_terraform(tmp_path) -> None:
    _write(tmp_path, {"main.tf": CALL_NET, ".terraform/m/main.tf": SG})
    caches: list[Path] = []
    assert _tfjson.tf_source_files(tmp_path, caches=caches) == [tmp_path / "main.tf"]
    assert caches == [tmp_path / ".terraform"]


def test_diff_scans_dot_terraform_when_the_caller_changes(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"a.tf": "locals {}\n", ".gitignore": ".terraform/\n"})
    _write(repo, {".terraform/m/main.tf": SG})
    _commit(repo, {"main.tf": CALL_NET})
    assert _diff_scan(repo).returncode == 1


def test_diff_scans_dot_terraform_when_the_module_changes(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r", {"main.tf": CALL_NET, ".terraform/m/main.tf": "locals {}\n"}
    )
    _commit(repo, {".terraform/m/main.tf": SG})
    proc = _diff_scan(repo)
    assert proc.returncode == 1, proc.stderr
    assert _hits(proc, SG_RULE)


def test_diff_reaches_callers_up_a_chain_through_dot_terraform(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": 'module "a" {\n  source = "./.terraform/a"\n}\n',
            ".terraform/a/main.tf": 'module "b" {\n  source = "../b"\n}\n',
            ".terraform/b/main.tf": "locals {}\n",
            "other/z.tf": "locals {}\n",
        },
    )
    _commit(repo, {".terraform/b/main.tf": 'output "x" {\n  value = 1\n}\n'})
    files = _diff.get_diff_files(repo, "main")
    assert {
        (repo / "main.tf").resolve(),
        (repo / ".terraform" / "a" / "main.tf").resolve(),
    } <= files
    assert (repo / "other" / "z.tf").resolve() not in files


def test_a_changed_uncalled_dot_terraform_file_adds_nothing(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": "locals {}\n",
            "modules/net/main.tf": SG,
            ".terraform/stale/main.tf": 'module "n" {\n  source = "../../modules/net"\n}\n',
        },
    )
    _commit(
        repo,
        {
            ".terraform/stale/main.tf": 'module "n" {\n  source = "../../modules/net"\n}\n\n'
        },
    )
    proc = _diff_scan(repo)
    assert proc.returncode == 0, proc.stderr
    assert not _hits(proc, SG_RULE)
