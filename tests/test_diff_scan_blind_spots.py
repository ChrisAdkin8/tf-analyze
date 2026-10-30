"""Three gate bypasses in what a scan reads.

* `--mode diff` never scanned a changed `.tfvars` or workflow file, so a
  secret added to `prod.auto.tfvars` passed the gate.
* A changed path with a non-ASCII byte came out of git quoted
  (`"caf\\303\\251/main.tf"`), named no file and was dropped.
* A module in `.terraform/` was never scanned, even when a local `source`
  called it and real Terraform loaded it.

Then what a review of those fixes found: anything committed under
`.terraform/` is code, not a cache; a `source` that isn't a plain string;
changes git can't name file by file (folder links, submodules).
"""

from __future__ import annotations

import json
import shutil
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


def test_a_changed_uncalled_untracked_dot_terraform_file_adds_nothing(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n", "modules/net/main.tf": SG})
    _write(repo, {".terraform/stale/main.tf": 'module "n" {\n  source = "../../modules/net"\n}\n'})
    proc = _diff_scan(repo)
    assert proc.returncode == 0, proc.stderr
    assert not _hits(proc, SG_RULE)
# ---- tracked files under .terraform are code, not a cache -------------------

MANIFEST = (
    '{"Modules":[{"Key":"","Source":"","Dir":"."},'
    '{"Key":"%s","Source":"%s","Dir":".terraform/modules/%s"}]}'
)
REGISTRY_CALL = 'module "vpc" {\n  source  = "terraform-aws-modules/vpc/aws"\n  version = "5.0.0"\n}\n'


def test_a_tracked_file_in_dot_terraform_is_scanned_though_nothing_calls_it(
    tmp_path,
) -> None:
    repo = _repo(
        tmp_path / "r", {"main.tf": "locals {}\n", ".terraform/stale/main.tf": SG}
    )
    assert _hits(_scan(repo), SG_RULE)
    _commit(repo, {".terraform/stale/main.tf": SG + "\n"})
    assert _hits(_diff_scan(repo), SG_RULE)


def test_a_force_added_file_in_an_ignored_dot_terraform_is_tracked(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r", {"main.tf": "locals {}\n", ".gitignore": ".terraform/\n"}
    )
    _write(repo, {".terraform/m/main.tf": SG, ".terraform/m/untracked.tf": SG})
    _git(repo, "add", "-f", ".terraform/m/main.tf")
    _git(repo, "commit", "-qm", "pr")
    assert [Path(f).name for f in _hits(_scan(repo), SG_RULE)] == ["main.tf"]


def test_a_tracked_tfvars_in_dot_terraform_is_scanned(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r", {"variables.tf": PASSWORD_VAR, ".terraform/m/a.tfvars": SECRET}
    )
    assert _hits(_scan(repo), SECRET_RULE)
    (repo / ".terraform" / "m" / "b.tfvars").write_text(SECRET)  # untracked
    assert len(_hits(_scan(repo), SECRET_RULE)) == 1


def test_ignore_paths_cover_a_tracked_file_in_dot_terraform(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": "locals {}\n",
            ".terraform/m/main.tf": SG,
            ".tf-analyze.yaml": "ignore_paths:\n  - .terraform/\n",
        },
    )
    assert not _hits(_scan(repo), SG_RULE)


def test_a_tracked_file_in_a_linked_folders_dot_terraform_is_scanned(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r", {"shared/.terraform/m/main.tf": SG, "app/x.tf": "locals {}\n"}
    )
    (repo / "app" / "net").symlink_to(repo / "shared", target_is_directory=True)
    hits = _hits(_scan(repo / "app"), SG_RULE)
    assert hits == [
        str((repo / "app").resolve() / "net" / ".terraform" / "m" / "main.tf")
    ]


def test_a_repo_with_no_dot_terraform_never_asks_git_for_tracked_files(
    tmp_path, monkeypatch
) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    monkeypatch.setattr(
        _diff, "tracked_cache_files", lambda *a: pytest.fail("asked git")
    )
    assert _diff.walk_tf_files(repo) == [repo / "main.tf"]


# Finding 4: Terraform loads what a committed manifest points at.


def test_a_committed_manifest_cannot_hide_a_registry_module(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": REGISTRY_CALL})
    _commit(
        repo,
        {
            ".terraform/modules/vpc/main.tf": SG,
            ".terraform/modules/modules.json": MANIFEST
            % ("vpc", "registry.terraform.io/terraform-aws-modules/vpc/aws", "vpc"),
        },
    )
    assert _scan(repo).returncode == 1
    assert _diff_scan(repo).returncode == 1


def test_a_committed_manifest_cannot_redirect_a_local_source(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": 'module "n" {\n  source = "./good"\n}\n',
            "good/main.tf": "locals {}\n",
            ".terraform/modules/evil/main.tf": SG,
            ".terraform/modules/modules.json": MANIFEST % ("n", "./good", "evil"),
        },
    )
    assert _scan(repo).returncode == 1


# Finding 1: a `source` that isn't a plain string.

NOT_PLAIN = [
    '("./.terraform/m")',
    '(\n    "./.terraform/m"\n  )',
    '"${"./.terraform/m"}"',
    '"./.terraform/${"m"}"',
    'true ? "./.terraform/m" : "./x"',
    '"./.terraf\\u006frm/m"',
]


@pytest.mark.parametrize("source", NOT_PLAIN)
def test_a_source_that_is_not_plain_cannot_hide_a_tracked_module(
    tmp_path, source
) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": f'module "n" {{\n  source = {source}\n}}\n',
            ".terraform/m/main.tf": SG,
        },
    )
    assert _scan(repo).returncode == 1


@pytest.mark.parametrize("source", NOT_PLAIN)
def test_a_source_that_is_not_plain_gets_a_warn_without_git(tmp_path, source) -> None:
    _write(
        tmp_path,
        {
            "main.tf": f'module "n" {{\n  source = {source}\n}}\n',
            ".terraform/m/main.tf": SG,
        },
    )
    assert "cannot tell which folder module source" in _scan(tmp_path).stderr


@pytest.mark.parametrize(
    "source",
    ['"./.terraform/m"', '"hashicorp/vpc/aws"', '"git::https://e.com/a.git?ref=$v"'],
    ids=["local", "registry", "dollar"],
)
def test_a_plain_source_gets_no_warn(tmp_path, source) -> None:
    _write(
        tmp_path,
        {"main.tf": f'module "n" {{\n  source = {source}\n}}\n', ".terraform/x": ""},
    )
    assert "module source" not in _scan(tmp_path).stderr


def test_no_warn_without_a_dot_terraform_folder(tmp_path) -> None:
    _write(tmp_path, {"main.tf": 'module "n" {\n  source = ("./x")\n}\n'})
    assert "module source" not in _scan(tmp_path).stderr


def test_a_comment_across_lines_in_the_block_header_hides_no_call(tmp_path) -> None:
    text = 'module /* a\n */ "n" /* b\n */ {\n  source /* c */ = /* d */ "./m"\n}\n'
    assert _diff.local_module_sources(Path("/r/main.tf"), text) == [Path("/r/m")]


def test_the_argument_after_a_source_is_not_part_of_it(tmp_path) -> None:
    text = 'module "n" {\n  source = "./a" # note\n  version = "1"\n  count = 1\n}\n'
    assert _diff.module_sources(Path("/r/main.tf"), text) == ([Path("/r/a")], [])


def test_diff_scans_everything_while_a_source_is_not_plain(tmp_path) -> None:
    # The diff can't see that main.tf calls `net`, so narrowing would miss it.
    call = 'module "n" {\n  source = ("./net")\n  c = "%s"\n}\n'
    repo = _repo(tmp_path / "r", {"net/main.tf": SG, "main.tf": call % "a"})
    _commit(repo, {"main.tf": call % "b"})
    proc = _diff_scan(repo)
    assert "cannot narrow the diff" in proc.stderr
    assert proc.returncode == 1, proc.stderr


# Finding 5: Terraform cleans `..` as text, before following links.


def test_dot_dot_after_a_symlink_is_cleaned_as_text(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "n" {\n  source = "./lnk/../.terraform/m"\n}\n',
            ".terraform/m/main.tf": SG,
            "x/y/keep.txt": "",
        },
    )
    (tmp_path / "lnk").symlink_to("x/y", target_is_directory=True)
    assert _scan(tmp_path).returncode == 1


def test_a_module_input_reaches_a_child_through_dot_dot_after_a_symlink(
    tmp_path,
) -> None:
    child = SG.replace('["0.0.0.0/0"]', "[var.c]")
    _write(
        tmp_path,
        {
            "main.tf": 'module "n" {\n  source = "./lnk/../net"\n  c = "0.0.0.0/0"\n}\n',
            "net/main.tf": 'variable "c" {}\n' + child,
            "x/y/keep.txt": "",
        },
    )
    (tmp_path / "lnk").symlink_to("x/y", target_is_directory=True)
    assert _hits(_scan(tmp_path), SG_RULE)


# Finding 6: a module in a linked folder keeps the link's spelling.


def test_a_linked_folder_with_no_tf_files_of_its_own_reaches_dot_terraform(
    tmp_path,
) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "shared/app/main.tf": 'module "n" {\n  source = "../.terraform/m"\n}\n',
            "infra/main.tf": "locals {}\n",
            ".gitignore": ".terraform/\n",
        },
    )
    _write(repo, {"shared/.terraform/m/main.tf": SG})
    (repo / "infra" / "net").symlink_to("../shared", target_is_directory=True)
    proc = _scan(repo / "infra")
    want = (repo / "infra").resolve() / "net" / ".terraform" / "m" / "main.tf"
    assert _hits(proc, SG_RULE) == [str(want)]
    assert "resolves outside the target" not in proc.stderr


# Finding 9: an ignored module calls nothing.


def test_an_ignored_module_in_the_middle_of_a_chain_reaches_nothing(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "n" {\n  source = "./vendor/mod"\n}\n',
            "vendor/mod/main.tf": 'module "c" {\n  source = "../../.terraform/m"\n}\n',
            ".terraform/m/main.tf": SG,
            ".tf-analyze.yaml": "ignore_paths:\n  - vendor/\n",
        },
    )
    proc = _scan(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert not _hits(proc, SG_RULE)


# Findings 2, 3 and 10: a change git can't name file by file.


def test_repointing_a_folder_symlink_scans_everything(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "main.tf": 'module "n" {\n  source = "./modules/cur"\n}\n',
            "modules/good/main.tf": "locals {}\n",
            "modules/bad/main.tf": SG,
        },
    )
    (repo / "modules" / "cur").symlink_to("good", target_is_directory=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "link")
    (repo / "modules" / "cur").unlink()
    (repo / "modules" / "cur").symlink_to("bad", target_is_directory=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pr")
    assert _diff.get_diff_files(repo, "main") is None
    proc = _diff_scan(repo)
    assert "is a folder link or submodule" in proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_a_new_folder_symlink_out_of_the_target_scans_everything(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "infra/main.tf": 'module "n" {\n  source = "./net"\n}\n',
            "shared/bad/main.tf": SG,
        },
    )
    (repo / "infra" / "net").symlink_to("../shared/bad", target_is_directory=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pr")
    assert _diff_scan(repo / "infra").returncode == 1


def test_a_submodule_bump_scans_everything(tmp_path) -> None:
    inner = _repo(tmp_path / "inner", {"main.tf": "locals {}\n"})
    _git(inner, "switch", "-q", "main")
    repo = _repo(
        tmp_path / "outer", {"main.tf": 'module "n" {\n  source = "./mods/net"\n}\n'}
    )
    _git(repo, "switch", "-q", "main")
    _git(
        repo,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        str(inner),
        "mods/net",
    )
    _git(repo, "commit", "-qm", "add")
    _git(repo, "switch", "-qc", "bump")
    (repo / "mods" / "net" / "main.tf").write_text(SG)
    _git(repo / "mods" / "net", "config", "user.email", "t@example.com")
    _git(repo / "mods" / "net", "config", "user.name", "t")
    _git(repo / "mods" / "net", "commit", "-qam", "x")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "bump")
    assert _diff.get_diff_files(repo, "main") is None
    assert _diff_scan(repo).returncode == 1


def test_an_untracked_git_checkout_in_dot_terraform_is_no_change(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    nested = repo / ".terraform" / "modules" / "vpc"
    nested.mkdir(parents=True)
    _git(nested, "init", "-q")
    _write(repo, {"a.tf": "locals {}\n"})
    _git(repo, "add", "a.tf")
    _git(repo, "commit", "-qm", "pr")
    assert (repo / "a.tf").resolve() in _diff.get_diff_files(repo, "main")


@pytest.mark.parametrize(
    "links", [{"loop.tf": "loop.tf"}, {"la": "lb", "lb": "la"}], ids=["self", "pair"]
)
def test_a_symlink_loop_in_a_pr_cannot_break_diff_mode(tmp_path, links) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    _write(repo, {"open.tf": SG})
    for name, dest in links.items():
        (repo / name).symlink_to(dest)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "pr")
    proc = _diff_scan(repo)
    assert proc.returncode == 1, proc.stderr
    assert _hits(proc, SG_RULE)


def test_a_path_with_no_real_path_cannot_be_narrowed(tmp_path, monkeypatch) -> None:
    # What Python 3.12 and older do with a symlink loop.
    def loop(self, strict=False):
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(Path, "resolve", loop)
    with pytest.raises(_diff._CannotNarrow):
        _diff._changed_path(tmp_path / "gone.tf")


def test_a_changed_symlink_loop_scans_everything_on_every_python(tmp_path) -> None:
    (tmp_path / "loop.tf").symlink_to("loop.tf")
    with pytest.raises(_diff._CannotNarrow):
        _diff._changed_path(tmp_path / "loop.tf")
    assert _diff._changed_path(tmp_path / "deleted.tf") == (tmp_path / "deleted.tf").resolve()


# Finding 7: a failed `ls-files` is not an empty list.


@pytest.mark.parametrize("failure", ["exit", "hang"])
def test_a_failed_untracked_listing_scans_everything(
    tmp_path, monkeypatch, failure
) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    real = _diff._run_git

    def run(argv, target, **kw):
        if "--others" not in argv:
            return real(argv, target, **kw)
        if failure == "hang":
            return None
        return subprocess.CompletedProcess(argv, 128, b"", b"fatal: broken\n")

    monkeypatch.setattr(_diff, "_run_git", run)
    assert _diff.get_diff_files(repo, "main") is None


# Round two: what the second review found.


def _failing_tracked_listing(monkeypatch) -> None:
    real = _diff._run_git

    def run(argv, target, **kw):
        if "--literal-pathspecs" in argv:
            return subprocess.CompletedProcess(argv, 128, b"", b"fatal: index corrupt\n")
        return real(argv, target, **kw)

    monkeypatch.setattr(_diff, "_run_git", run)


def test_a_failed_tracked_listing_is_reported_not_taken_for_empty(tmp_path, monkeypatch) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n", ".terraform/m/main.tf": SG})
    _failing_tracked_listing(monkeypatch)
    unknown: list[Path] = []
    assert _diff.walk_tf_files(repo, unknown=unknown) == [repo / "main.tf"]
    assert unknown == [repo / ".terraform"]


def test_a_failed_tracked_listing_scans_everything_in_diff_mode(tmp_path, monkeypatch) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n", ".terraform/m/main.tf": "locals {}\n"})
    _commit(repo, {".terraform/m/main.tf": SG})
    _failing_tracked_listing(monkeypatch)
    assert _diff.get_diff_files(repo, "main") is None


def test_no_git_warns_about_a_dot_terraform_with_code_and_scans_none_of_it(tmp_path) -> None:
    _write(tmp_path, {"main.tf": "locals {}\n", ".terraform/modules/x/main.tf": SG})
    proc = _scan(tmp_path)
    assert proc.stderr.count("cannot tell which files git tracks in") == 1
    assert str(tmp_path.resolve() / ".terraform") in proc.stderr
    assert proc.returncode == 0, proc.stderr


def test_no_git_warn_covers_a_tfvars_only_cache(tmp_path) -> None:
    _write(tmp_path, {"main.tf": "locals {}\n", ".terraform/x/a.tfvars": SECRET})
    assert "cannot tell which files git tracks" in _scan(tmp_path).stderr


def test_no_warn_for_a_dot_terraform_with_no_terraform_files(tmp_path) -> None:
    _write(tmp_path, {"main.tf": "locals {}\n", ".terraform/providers/binary": "x"})
    assert "cannot tell which files git tracks" not in _scan(tmp_path).stderr


def test_a_broken_dot_git_file_gets_the_same_warn(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n", ".terraform/m/main.tf": SG})
    shutil.rmtree(repo / ".git")
    (repo / ".git").write_text("gitdir: /nonexistent/x\n")
    assert "cannot tell which files git tracks" in _scan(repo).stderr


def _verify(repo: Path, prior: Path) -> subprocess.CompletedProcess:
    return _scan(repo, "--mode", "verify-fixed", "--prior-report", str(prior))


def test_verify_fixed_does_not_resolve_a_finding_in_a_skipped_cache(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n", ".terraform/m/main.tf": SG})
    prior = tmp_path / "prior.json"
    prior.write_text(_scan(repo).stdout)
    assert json.loads(_verify(repo, prior).stdout)["results"]["STILL-PRESENT"]
    shutil.rmtree(repo / ".git")  # now nothing says it's tracked
    proc = _verify(repo, prior)
    results = json.loads(proc.stdout)["results"]
    assert not results["RESOLVED"] and results["UNREADABLE"]
    assert proc.returncode != 0
    (repo / ".terraform" / "m" / "main.tf").unlink()  # really gone
    assert not json.loads(_verify(repo, prior).stdout)["results"]["UNREADABLE"]


def test_a_glob_character_in_a_linked_folder_hides_no_tracked_code(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r", {"sh[a]red/.terraform/m/main.tf": SG, "infra/x.tf": "locals {}\n"}
    )
    (repo / "infra" / "net").symlink_to("../sh[a]red", target_is_directory=True)
    assert _hits(_scan(repo / "infra"), SG_RULE)


def test_gitmodules_cannot_hide_a_submodule_bump(tmp_path) -> None:
    inner = _repo(tmp_path / "inner", {"main.tf": "locals {}\n"})
    _git(inner, "switch", "-q", "main")
    repo = _repo(tmp_path / "outer", {"main.tf": 'module "n" {\n  source = "./net"\n}\n'})
    _git(repo, "switch", "-q", "main")
    _git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner), "net")
    _git(repo, "commit", "-qm", "add")
    _git(repo, "switch", "-qc", "bump")
    (repo / "net" / "main.tf").write_text(SG)
    _git(repo / "net", "config", "user.email", "t@example.com")
    _git(repo / "net", "config", "user.name", "t")
    _git(repo / "net", "commit", "-qam", "x")
    _git(repo, "add", "-A")
    gitmodules = repo / ".gitmodules"
    gitmodules.write_text(gitmodules.read_text() + "\tignore = all\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "bump")
    assert _diff.get_diff_files(repo, "main") is None
    assert _diff_scan(repo).returncode == 1


def test_gitattributes_cannot_hide_a_change(tmp_path) -> None:
    repo = _repo(tmp_path / "r", {"main.tf": "locals {}\n"})
    _commit(repo, {".gitattributes": "*.tf -diff diff=nope\n", "main.tf": SG})
    assert _diff_scan(repo).returncode == 1


def test_an_ignored_file_cannot_turn_diff_mode_off(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            ".tf-analyze.yaml": "ignore_paths:\n  - fixtures/\n",
            "fixtures/x/main.tf": 'module "x" {\n  source = ("./y")\n}\n',
            "legacy.tf": SG,
            "app/main.tf": "locals {}\n",
        },
    )
    _commit(repo, {"app/o.tf": "locals {}\n"})
    proc = _diff_scan(repo)
    assert proc.returncode == 0, proc.stderr
    assert "cannot narrow" not in proc.stderr


def test_a_source_that_is_not_plain_stays_on_one_line_in_the_warn(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "a" {\n  source = (\n"::error::forged"\n)\n}\n',
            ".terraform/x": "",
        },
    )
    stderr = _scan(tmp_path).stderr
    assert "forged" in stderr
    assert not [line for line in stderr.splitlines() if line.startswith(('"::', "::"))]


def _lnk(root: Path) -> None:
    (root / "x" / "y").mkdir(parents=True)
    (root / "lnk").symlink_to("x/y", target_is_directory=True)


def test_sensitive_input_check_follows_dot_dot_after_a_symlink(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'variable "p" {\n  sensitive = true\n}\n'
            'module "n" {\n  source   = "./lnk/../net"\n  password = var.p\n}\n',
            "net/main.tf": 'variable "password" {}\n',
        },
    )
    _lnk(tmp_path)
    assert _hits(_scan(tmp_path), "SEC-SENSITIVE-002")


def test_unused_module_check_follows_dot_dot_after_a_symlink(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "n" {\n  source = "./lnk/../net"\n}\n',
            "net/main.tf": 'variable "a" {\n  default = 1\n}\n',
        },
    )
    _lnk(tmp_path)
    assert not _hits(_scan(tmp_path), "MOD-UNUSED-001")


def test_unused_output_check_follows_dot_dot_after_a_symlink(tmp_path) -> None:
    _write(
        tmp_path,
        {
            "main.tf": 'module "n" {\n  source = "./lnk/../net"\n}\n',
            "net/main.tf": 'output "o" {\n  value = 1\n}\n',
        },
    )
    _lnk(tmp_path)
    assert _hits(_scan(tmp_path), "ROB-UNUSED-002")


# Finding 8: `.terraform` is judged from the target down.


def test_a_target_inside_dot_terraform_scans_its_tfvars(tmp_path) -> None:
    _write(
        tmp_path,
        {".terraform/app/v.tf": PASSWORD_VAR, ".terraform/app/a.auto.tfvars": SECRET},
    )
    proc = _scan(tmp_path / ".terraform" / "app")
    assert proc.returncode == 1, proc.stderr
    assert _hits(proc, SECRET_RULE)


def test_a_dot_terraform_below_such_a_target_is_still_skipped(tmp_path) -> None:
    _write(
        tmp_path,
        {
            ".terraform/app/v.tf": PASSWORD_VAR,
            ".terraform/app/.terraform/old/a.auto.tfvars": SECRET,
        },
    )
    assert not _hits(_scan(tmp_path / ".terraform" / "app"), SECRET_RULE)


# The two git arguments no test pinned down.


def test_an_untracked_file_under_a_subfolder_target_is_named_from_the_repo_root(
    tmp_path,
) -> None:
    repo = _repo(tmp_path / "r", {"infra/main.tf": "locals {}\n"})
    _write(repo, {"infra/new.tf": SG})
    assert (repo / "infra" / "new.tf").resolve() in _diff.get_diff_files(
        repo / "infra", "main"
    )
    assert _hits(_diff_scan(repo / "infra"), SG_RULE)


def test_a_change_in_a_folder_linked_from_outside_the_target_is_seen(tmp_path) -> None:
    repo = _repo(
        tmp_path / "r", {"app/x.tf": "locals {}\n", "shared/main.tf": "locals {}\n"}
    )
    (repo / "app" / "net").symlink_to("../shared", target_is_directory=True)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "link")
    _git(repo, "branch", "-f", "main", "HEAD")
    _commit(repo, {"shared/main.tf": SG})
    assert (repo / "shared" / "main.tf").resolve() in _diff.get_diff_files(
        repo / "app", "main"
    )
    assert _hits(_diff_scan(repo / "app"), SG_RULE)
