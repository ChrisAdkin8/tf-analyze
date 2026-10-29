"""Scan-coverage gaps (critical review): files, rules and findings that
were silently left out of a scan.

* A file with one non-UTF-8 byte (a Latin-1 ``é`` in a comment) was
  dropped whole; on Windows the locale codec broke valid UTF-8 too.
* A commented-out provider pin overrode the real one and switched
  ``applies_when`` rules off.
* One tree-wide provider pin: a child module pinning an old provider
  switched rules off for the root module too.
* Symlinked module folders were never walked.
* ``--mode diff`` missed a caller whose child module changed.
* A trailing ``# tf-analyze:ignore`` also silenced the next line.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import _diff
import _tfjson
import _versions
import detect
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

AKS = (
    'resource "azurerm_kubernetes_cluster" "k" {\n'
    '  name                              = "k"\n'
    "  role_based_access_control_enabled = false\n"
    "}\n"
)
AKS_RULE = "SEC-AZURE-AKS-001"  # applies_when: azurerm >= 3.x


def _pin(version: str) -> str:
    return (
        "terraform {\n  required_providers {\n    azurerm = {\n"
        '      source  = "hashicorp/azurerm"\n'
        f'      version = "{version}"\n'
        "    }\n  }\n}\n"
    )


def _scan(target: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _hits(proc: subprocess.CompletedProcess, rule: str) -> list[tuple[str, int]]:
    return sorted(
        (f["file"], f["line"])
        for f in json.loads(proc.stdout)["findings"]
        if f["id"] == rule
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)


# ---- A: encoding ----------------------------------------------------------


def test_non_utf8_byte_does_not_drop_the_file(tmp_path) -> None:
    (tmp_path / "main.tf").write_bytes(
        "# Owner: Jos\xe9\n".encode("latin-1") + SG.encode()
    )
    proc = _scan(tmp_path)
    # Scanned, on the right line, and the bad byte is reported.
    assert _hits(proc, SG_RULE) == [(str(tmp_path / "main.tf"), 2)], proc.stderr
    assert "not valid UTF-8" in proc.stderr
    assert "cannot read" not in proc.stderr


def test_read_normalized_is_utf8_whatever_the_locale(tmp_path) -> None:
    p = tmp_path / "x.tf"
    p.write_bytes("﻿# café\r\nlocals {}\r\n".encode())
    assert detect._read_normalized(p) == "# café\nlocals {}\n"  # BOM dropped
    p.write_bytes(b"# caf\xe9\nlocals {}\n")
    assert detect._read_normalized(p) == "# caf�\nlocals {}\n"


# ---- B: pins in comments --------------------------------------------------


def test_commented_out_pins_are_not_read() -> None:
    text = (
        'terraform {\n  required_version = ">= 1.5"\n'
        '  # required_version = "< 1.0"\n'
        "  required_providers {\n"
        '    azurerm = {\n      version = "~> 3.100"\n    }\n'
        '    # was: azurerm = { version = "~> 2.99" }\n'
        "  }\n}\n"
        '/*\nterraform {\n  required_version = "< 0.12"\n'
        '  required_providers {\n    azurerm = { version = "~> 2.99" }\n  }\n}\n*/\n'
    )
    assert _versions._extract_provider_constraints({"m.tf": text}) == {
        "azurerm": "~> 3.100"
    }
    assert (
        _versions._extract_terraform_version({"m.tf": text[text.index("/*") :]}) == ""
    )
    assert _versions._extract_terraform_version({"m.tf": text}) == ">= 1.5"


def test_commented_out_pin_does_not_skip_rules(tmp_path) -> None:
    pin = _pin("~> 3.100").replace(
        "    }\n  }\n}\n",
        '    }\n    # was: azurerm = { version = "~> 2.99" }\n  }\n}\n',
    )
    (tmp_path / "main.tf").write_text(pin + AKS)
    proc = _scan(tmp_path)
    assert _hits(proc, AKS_RULE), proc.stderr
    assert "skipped due to applies_when" not in proc.stderr


# ---- C: pins are per module folder ----------------------------------------


def test_child_module_pin_does_not_gate_the_root(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(AKS)
    legacy = tmp_path / "modules" / "legacy"
    legacy.mkdir(parents=True)
    (legacy / "versions.tf").write_text(_pin("~> 2.99"))
    (legacy / "main.tf").write_text(AKS)
    proc = _scan(tmp_path)
    # The root has no pin (not gated); the legacy module's pin rules the
    # rule out for its own files only.
    assert _hits(proc, AKS_RULE) == [(str(tmp_path / "main.tf"), 1)], proc.stderr
    assert "skipped in 1 folder(s) due to applies_when" in proc.stderr


def test_a_pin_ruling_a_rule_out_everywhere_still_skips_it(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(_pin("~> 2.99") + AKS)
    proc = _scan(tmp_path)
    assert not _hits(proc, AKS_RULE)
    assert "rule(s) skipped due to applies_when" in proc.stderr


def _module_call(name: str, source: str) -> str:
    return f'module "{name}" {{\n  source = "{source}"\n}}\n'


def test_unpinned_child_is_gated_by_its_callers_pin(tmp_path) -> None:
    # The child runs under the root's azurerm ~> 2.99, so the >= 3 rule
    # must not fire in it.
    (tmp_path / "main.tf").write_text(
        _pin("~> 2.99") + _module_call("aks", "./modules/aks")
    )
    child = tmp_path / "modules" / "aks"
    child.mkdir(parents=True)
    (child / "main.tf").write_text(AKS)
    proc = _scan(tmp_path)
    assert not _hits(proc, AKS_RULE), proc.stderr


def test_child_with_two_callers_is_gated_only_if_both_rule_it_out(tmp_path) -> None:
    child = tmp_path / "modules" / "aks"
    child.mkdir(parents=True)
    (child / "main.tf").write_text(AKS)
    for env, pin in (("old", "~> 2.99"), ("new", "~> 3.100")):
        (tmp_path / env).mkdir()
        (tmp_path / env / "main.tf").write_text(
            _pin(pin) + _module_call("aks", "../modules/aks")
        )
    proc = _scan(tmp_path)
    assert _hits(proc, AKS_RULE) == [(str(child / "main.tf"), 1)], proc.stderr
    # Both callers old: ruled out.
    (tmp_path / "new" / "main.tf").write_text(
        _pin("~> 2.90") + _module_call("aks", "../modules/aks")
    )
    assert not _hits(_scan(tmp_path), AKS_RULE)


def test_uncalled_folder_falls_back_to_its_nearest_pinned_ancestor(tmp_path) -> None:
    (tmp_path / "versions.tf").write_text(_pin("~> 2.99"))
    orphan = tmp_path / "stacks" / "aks"
    orphan.mkdir(parents=True)
    (orphan / "main.tf").write_text(AKS)
    assert not _hits(_scan(tmp_path), AKS_RULE)


def test_effective_constraints() -> None:
    own = {
        "/r": ({"azurerm": "~> 2.99"}, ""),
        "/r/m": ({"azurerm": ">= 2.0"}, ">= 1.5"),
    }
    callers = {"/r/m": {"/r"}, "/x": {"/r/m"}}
    got = _versions._effective_constraints(
        own, callers, ["/r", "/r/m", "/x", "/y"], "/r"
    )
    assert got["/r"] == [({"azurerm": "~> 2.99"}, "")]
    assert got["/r/m"] == [({"azurerm": ">= 2.0, ~> 2.99"}, ">= 1.5")]
    assert got["/x"] == got["/r/m"]  # through the call chain
    assert got["/y"] == [({}, "")]  # outside the root, called by no one: ungated


def test_constraints_by_dir() -> None:
    got = _versions._constraints_by_dir(
        {
            Path("/r/main.tf"): AKS,
            Path("/r/m/versions.tf"): _pin("~> 2.99"),
            Path("/r/m/main.tf"): 'terraform {\n  required_version = ">= 1.5"\n}\n',
        }
    )
    assert got == {str(Path("/r/m")): ({"azurerm": "~> 2.99"}, ">= 1.5")}


# ---- D: symlinked module folders --------------------------------------------


needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks need privileges on Windows"
)


def _linked_repo(tmp_path: Path) -> Path:
    (tmp_path / "root").mkdir()
    (tmp_path / "shared").mkdir()
    (tmp_path / "root" / "main.tf").write_text(
        'module "net" {\n  source = "./net"\n}\n'
    )
    (tmp_path / "shared" / "main.tf").write_text(SG)
    os.symlink("../shared", tmp_path / "root" / "net")
    os.symlink("net", tmp_path / "root" / "net2")  # second path to the same folder
    os.symlink("..", tmp_path / "root" / "up")  # a parent: never walked
    return tmp_path / "root"


@needs_symlinks
def test_symlinked_module_in_the_repo_is_scanned_once(tmp_path) -> None:
    root = _linked_repo(tmp_path)
    _git(tmp_path, "init", "-q")
    proc = _scan(root)
    assert _hits(proc, SG_RULE) == [(str(root / "net" / "main.tf"), 1)], proc.stderr
    assert "not following 1 symlinked folder(s)" in proc.stderr  # `up`


@needs_symlinks
def test_linked_file_outside_the_target_is_never_patched(tmp_path) -> None:
    root = _linked_repo(tmp_path)
    _git(tmp_path, "init", "-q")
    before = (tmp_path / "shared" / "main.tf").read_text()
    proc = _scan(root, "--apply-fixes", "apply")
    # Scanned (so a fix was offered), but the write was refused.
    assert "resolves outside the scan target" in proc.stderr
    assert (tmp_path / "shared" / "main.tf").read_text() == before
    assert not list((tmp_path / "shared").glob("*.bak*"))


@needs_symlinks
def test_sarif_uri_for_a_linked_file_is_its_repo_path(tmp_path) -> None:
    root = _linked_repo(tmp_path)
    _git(tmp_path, "init", "-q")
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(root),
            "--format",
            "sarif",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    uris = {
        loc["physicalLocation"]["artifactLocation"]["uri"]
        for r in json.loads(proc.stdout)["runs"][0]["results"]
        if r["ruleId"] == SG_RULE
        for loc in r["locations"]
    }
    assert uris == {"shared/main.tf"}, uris  # the tracked file; no `../`


def test_work_tree_comes_from_git_not_a_stray_dot_git(tmp_path) -> None:
    (tmp_path / ".git").mkdir()  # not a repository
    (tmp_path / "t").mkdir()
    assert detect._git_work_tree(tmp_path / "t") is None
    repo = tmp_path / "r"
    (repo / "t").mkdir(parents=True)
    _git(repo, "init", "-q")
    assert detect._git_work_tree(repo / "t") == str(repo.resolve())


@needs_symlinks
def test_symlink_leaving_the_repo_is_not_followed_but_reported(tmp_path) -> None:
    root = _linked_repo(tmp_path)  # no git repository around it
    proc = _scan(root)
    assert not _hits(proc, SG_RULE)
    assert "not following 3 symlinked folder(s)" in proc.stderr
    assert str(root / "net") in proc.stderr


@needs_symlinks
def test_tf_source_files_follows_links_inside_root(tmp_path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "main.tf").write_text("locals {}\n")
    (tmp_path / ".terraform").mkdir()
    (tmp_path / ".terraform" / "x.tf").write_text("locals {}\n")
    os.symlink("a", tmp_path / "alias")
    os.symlink(".", tmp_path / "a" / "loop")
    skipped: list = []
    files = _tfjson.tf_source_files(tmp_path, skipped=skipped)
    assert files == [tmp_path / "a" / "main.tf"]  # real path wins; no loop
    assert skipped == []  # a/loop is walked once, as a


# ---- E: diff mode covers callers of a changed child module -------------------


def test_child_module_change_rescans_its_callers(tmp_path) -> None:
    repo = tmp_path / "r"
    (repo / "modules" / "net").mkdir(parents=True)
    (repo / "app").mkdir()
    (repo / "app" / "main.tf").write_text(
        'module "net" {\n  source = "../modules/net"\n}\n'
        'resource "aws_instance" "i" {\n'
        "  vpc_security_group_ids = [module.net.sg_id]\n}\n"
    )
    (repo / "other.tf").write_text("locals {}\n")
    out = 'output "sg_id" {\n  value = "%s"\n}\n'
    (repo / "modules" / "net" / "outputs.tf").write_text(out % "a")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.email=t@e", "-c", "user.name=t", "add", "-A")
    _git(repo, "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "base")
    _git(repo, "switch", "-qc", "pr")
    (repo / "modules" / "net" / "outputs.tf").write_text(out % "b")
    _git(repo, "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qam", "pr")
    files = _diff.get_diff_files(repo, "main")
    assert files == {
        (repo / "modules" / "net" / "outputs.tf").resolve(),
        (repo / "app" / "main.tf").resolve(),
    }


# ---- F: inline-ignore scope -------------------------------------------------


def test_trailing_ignore_covers_only_its_own_line() -> None:
    text = (
        'resource "x" "y" {\n'
        '  a = "1" # tf-analyze:ignore RULE-A\n'
        '  b = "2"\n'
        "  # tf-analyze:ignore RULE-B\n"
        '  c = "3"\n'
        "  // tf-analyze:ignore RULE-C\n"
        '  d = "4" // tf-analyze:ignore RULE-D\n'
        '  e = "# tf-analyze:ignore RULE-E"\n'
        "}\n"
    )
    got = detect.load_inline_suppressions(text)
    assert got == {
        2: {"RULE-A"},
        4: {"RULE-B"},
        5: {"RULE-B"},
        6: {"RULE-C"},
        7: {"RULE-C", "RULE-D"},
    }


def test_trailing_ignore_does_not_hide_the_next_line(tmp_path) -> None:
    # A trailing marker on the first group's closing brace (line 9) used
    # to cover line 10, where the second group opens.
    one = (
        SG.replace('"open"', '"one"', 1)[:-2] + "} # tf-analyze:ignore SEC-AWS-SG-001\n"
    )
    (tmp_path / "main.tf").write_text(one + SG.replace('"open"', '"two"', 1))
    proc = _scan(tmp_path)
    main = str(tmp_path / "main.tf")
    assert _hits(proc, SG_RULE) == [(main, 1), (main, 10)], proc.stderr


# ---- review round 2 ---------------------------------------------------------


@needs_symlinks
def test_verify_fixed_lists_files_like_the_scan(tmp_path) -> None:
    # It used its own walk, didn't follow the link, and called the
    # unchanged finding in net/main.tf RESOLVED.
    root = _linked_repo(tmp_path)
    _git(tmp_path, "init", "-q")
    report = tmp_path / "report.json"
    report.write_text(_scan(root).stdout)
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target", str(root),
         "--mode", "verify-fixed", "--prior-report", str(report), "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    res = json.loads(proc.stdout)["results"]
    still = {(f["id"], f["file"]) for f in res.get("STILL-PRESENT", [])}
    assert (SG_RULE, str(root / "net" / "main.tf")) in still, proc.stderr


def _commit_all(repo: Path, msg: str) -> None:
    _git(repo, "-c", "user.email=t@e", "-c", "user.name=t", "add", "-A")
    _git(repo, "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", msg)


@needs_symlinks
def test_diff_mode_sees_a_change_in_a_linked_module(tmp_path) -> None:
    root = _linked_repo(tmp_path)
    (tmp_path / "shared" / "main.tf").write_text("locals {}\n")
    _git(tmp_path, "init", "-q", "-b", "main")
    _commit_all(tmp_path, "base")
    _git(tmp_path, "switch", "-qc", "feat")
    (tmp_path / "shared" / "main.tf").write_text(SG)
    _commit_all(tmp_path, "open")
    assert (tmp_path / "shared" / "main.tf").resolve() in _diff.get_diff_files(root, "main")
    proc = _scan(root, "--mode", "diff", "--diff-base", "main")
    assert _hits(proc, SG_RULE) == [(str(root / "net" / "main.tf"), 1)], proc.stderr


@needs_symlinks
def test_links_into_terraform_cache_are_not_followed(tmp_path) -> None:
    cache = tmp_path / ".terraform" / "modules" / "vpc"
    cache.mkdir(parents=True)
    (cache / "main.tf").write_text("locals {}\n")
    (tmp_path / "main.tf").write_text("locals {}\n")
    os.symlink(".terraform/modules", tmp_path / "mods")
    skipped: list = []
    assert _tfjson.tf_source_files(tmp_path, skipped=skipped) == [tmp_path / "main.tf"]
    assert skipped == [tmp_path / "mods"]


def test_only_module_block_sources_are_module_calls() -> None:
    text = (
        '/*\nmodule "old" {\n  source = "../a"\n}\n*/\n'
        '# source = "../b"\n'
        'resource "null_resource" "x" {\n'
        '  provisioner "file" {\n    source      = "../c"\n    destination = "/tmp"\n  }\n'
        '  user_data = <<EOT\nmodule "h" {\n  source = "../d"\n}\nEOT\n'
        "}\n"
        'module "real" {\n'
        '  tags = { source = "../e" }\n'
        '  source = "./modules/f"\n'
        "}\n"
    )
    assert _diff.local_module_sources(Path("/r/main.tf"), text) == [
        Path("/r/modules/f")
    ]


def test_provisioner_source_does_not_make_a_caller(tmp_path) -> None:
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "main.tf").write_text(
        _pin("~> 2.99") + 'resource "null_resource" "x" {\n'
        '  provisioner "file" {\n    source      = "../shared"\n'
        '    destination = "/tmp/shared"\n  }\n}\n'
    )
    (tmp_path / "shared").mkdir()
    (tmp_path / "shared" / "main.tf").write_text(AKS)
    proc = _scan(tmp_path)
    assert _hits(proc, AKS_RULE) == [(str(tmp_path / "shared" / "main.tf"), 1)], proc.stderr


def test_too_many_alternatives_means_ungated() -> None:
    callers = {f"/r/e{i:02d}" for i in range(70)}
    own = {c: ({}, f"< 1.9, != 1.0.{i}") for i, c in enumerate(sorted(callers))}
    own["/r/e00"] = ({}, ">= 1.10")  # the one caller that allows the rule
    got = _versions._effective_constraints(own, {"/r/shared": callers}, ["/r/shared"], "/r")
    assert got["/r/shared"] == [({}, "")]


def test_utf16_and_binary_files_stay_unreadable(tmp_path) -> None:
    bucket = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
    for name, data in (
        ("utf16", bucket.encode("utf-16")),  # with its BOM
        ("utf16_no_bom", bucket.encode("utf-16-le")),
        ("binary", b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + b"locals {}\n"),
    ):
        d = tmp_path / name
        d.mkdir()
        (d / "main.tf").write_bytes(data)
        proc = _scan(d, "--fail-on", "HIGH")
        assert proc.returncode == 1, proc.stderr
        assert json.loads(proc.stdout)["summary"]["unreadable_files"] == [str(d / "main.tf")]


def test_a_stray_nul_in_a_comment_is_still_scanned(tmp_path) -> None:
    # NUL is valid UTF-8; main scanned such a file, so it must not become
    # "unreadable" and fail the gate.
    (tmp_path / "main.tf").write_bytes(
        b"# note \x00 here\n"
        b'resource "aws_s3_bucket_acl" "b" {\n  bucket = "b"\n  acl = "public-read"\n}\n'
    )
    proc = _scan(tmp_path)
    report = json.loads(proc.stdout)
    assert report["summary"].get("unreadable_files", []) == [], proc.stderr
    assert report["findings"], proc.stderr


def test_a_bare_module_label_is_a_module_call() -> None:
    text = 'module a {\n  source = "./m"\n}\nmodule "b" {\n  source = "./n"\n}\n'
    assert _diff.local_module_sources(Path("/r/main.tf"), text) == [
        Path("/r/m"), Path("/r/n")
    ]


def test_non_utf8_warning_offset_counts_the_bom(tmp_path, capsys) -> None:
    p = tmp_path / "bom.tf"
    p.write_bytes(b"\xef\xbb\xbf# caf\xe9\n")
    detect._read_normalized(p)
    assert "byte 0xe9 at offset 8" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("constraint", "minimum", "allowed"),
    [
        ("5.31.0", "5.0", True),  # bare exact pin above the minimum
        ("= 5.31.0", "5.0", True),
        ("= 4.9.0", "5.0", False),
        ("5.0.0", "5.0", True),
        ("1.11.0", "1.10", True),
        ("v1.11.0", "1.10", True),
        ("= 5.0.0-beta1", "5.0", True),  # pre-release compared by its numbers
        ("!= 5.0.0", "5.0", True),
        ("= 5.0.0, != 5.0.0", "5.0", False),
        ("= 5.1, = 5.2", "5.0", False),
        ("> 5.0", "5.0", True),
        ("> 4.0", "5.0", True),
        (">= 4.0", "5.0", True),
        ("< 5.0", "5.0", False),
        ("< 5.0.1", "5.0", True),
        ("<= 5.0", "5.0", True),
        ("<= 4.99", "5.0", False),
        (">= 5.0, <= 5.0", "5.0", True),
        (">= 5.0, <= 5.0, != 5.0.0", "5.0", False),
        ("~> 5.40", "5.0", True),
        ("~> 4.50", "5.0", False),
        ("~> 4.50.1", "4.51", False),  # 3 parts: < 4.51.0
        ("~> 4.50.1", "4.50", True),
        ("~> 3", "3.0", True),
        ("~> 3", "4.0", False),
        (">= 1.5.0, < 1.10", "1.10", False),
        (">= 1.5.0, < 1.11", "1.10", True),
        ("< 1.9, != 1.0.3", "1.10", False),
        ("garbage", "5.0", True),
        ("", "5.0", True),
    ],
)
def test_constraint_allows_table(constraint: str, minimum: str, allowed: bool) -> None:
    assert _versions._provider_constraint_allows(constraint, minimum) is allowed
