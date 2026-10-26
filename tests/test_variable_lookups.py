"""`var.X` / `local.X` resolution: comments, nested keys, `.tfvars` files
and child modules called from several places.

Each case uses SEC-AWS-RDS-001 (`publicly_accessible = true`) with the
value supplied indirectly, so the rule fires only if resolution works.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import detect

REPO = Path(__file__).resolve().parents[1]

DB = """resource "aws_db_instance" "a" {
  publicly_accessible = %s
  storage_encrypted   = true
}
"""


def _scan(target: Path) -> list[dict]:
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return [
        f for f in json.loads(out.stdout)["findings"] if f["id"] == "SEC-AWS-RDS-001"
    ]


def _var(default: str, comment: str = "") -> str:
    return f'variable "pub" {{\n  type    = bool\n  default = {default}{comment}\n}}\n'


# ---- comments after a value ------------------------------------------------------


def test_default_with_trailing_comments(tmp_path) -> None:
    for i, comment in enumerate(("  // note", "  # it's public", "  /* c */")):
        d = tmp_path / str(i)
        d.mkdir()
        (d / "main.tf").write_text(_var("true", comment) + DB % "var.pub")
        assert _scan(d), comment


# ---- locals -----------------------------------------------------------------------


def test_nested_key_does_not_shadow_a_local(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(
        "locals {\n  pub = true\n  defaults = {\n    pub = false\n  }\n}\n"
        + DB % "local.pub"
    )
    assert _scan(tmp_path)


# ---- .tfvars ----------------------------------------------------------------------


def test_terraform_tfvars_overrides_the_default(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(_var("false") + DB % "var.pub")
    (tmp_path / "terraform.tfvars").write_text("pub = true\n")
    assert _scan(tmp_path)


def test_auto_tfvars_precedence_and_json(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(_var("false") + DB % "var.pub")
    (tmp_path / "terraform.tfvars").write_text("pub = false\n")
    (tmp_path / "a.auto.tfvars.json").write_text(json.dumps({"pub": False}))
    (tmp_path / "b.auto.tfvars").write_text("pub = true # last wins\n")
    assert _scan(tmp_path)
    (tmp_path / "c.auto.tfvars.json").write_text(json.dumps({"pub": False}))
    assert not _scan(tmp_path)


def test_tfvars_symlinked_from_outside_is_not_read(tmp_path) -> None:
    outside = tmp_path / "outside.tfvars"
    outside.write_text("pub = true\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.tf").write_text(_var("false") + DB % "var.pub")
    (repo / "terraform.tfvars").symlink_to(outside)
    assert not _scan(repo)


# ---- child modules with several callers --------------------------------------------


def _child_with_callers(root: Path, *values: str) -> None:
    (root / "child").mkdir(parents=True)
    (root / "child" / "main.tf").write_text(_var("false") + DB % "var.pub")
    root.joinpath("main.tf").write_text(
        "".join(
            f'module "m{i}" {{\n  source = "./child"\n  pub    = {v}\n}}\n'
            for i, v in enumerate(values)
        )
    )


def test_each_caller_is_seen_whatever_the_order(tmp_path) -> None:
    for name, values in (("a", ("true", "false")), ("b", ("false", "true"))):
        _child_with_callers(tmp_path / name, *values)
        assert len(_scan(tmp_path / name)) == 1, values  # one finding, not two


def test_callers_passing_the_same_value_are_scanned_once(tmp_path) -> None:
    _child_with_callers(tmp_path, "true", "true", "true")
    child = str((tmp_path / "child").resolve())
    files = {p: p.read_text() for p in tmp_path.rglob("*.tf")}
    assert len(detect._extract_var_contexts_by_dir(files)[child]) == 1
    assert len(_scan(tmp_path)) == 1


def test_caller_value_resolved_through_its_own_variable(tmp_path) -> None:
    _child_with_callers(tmp_path, "var.expose")
    (tmp_path / "vars.tf").write_text('variable "expose" {\n  default = true\n}\n')
    assert _scan(tmp_path)


def test_module_call_cycle_terminates(tmp_path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "main.tf").write_text('module "b" {\n  source = "../b"\n}\n')
    (tmp_path / "b" / "main.tf").write_text(
        'module "a" {\n  source = "../a"\n}\n' + DB % "true"
    )
    assert _scan(tmp_path)  # and returns at all


def test_single_table_api_keeps_working(tmp_path) -> None:
    _child_with_callers(tmp_path, "true", "false")
    files = {p: p.read_text() for p in tmp_path.rglob("*.tf")}
    tables = detect._extract_var_defaults_by_dir(files)
    assert tables[str((tmp_path / "child").resolve())]["pub"] == "true"
