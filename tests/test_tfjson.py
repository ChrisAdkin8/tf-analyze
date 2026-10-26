"""`*.tf.json` support: the JSON → HCL renderer (`_tfjson`) and the scan
pipeline that uses it."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _hcl
import _tfjson
import detect
import pytest

REPO = Path(__file__).resolve().parents[1]

OPEN_SG = {
    "resource": {
        "aws_security_group": {
            "sg": {
                "name": "open",
                "ingress": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ],
                "tags": {"Name": "x"},
            }
        }
    }
}


def _render(doc: dict) -> str:
    return _tfjson.tf_json_to_hcl(json.dumps(doc, indent=2))


def _scan(target: Path, *extra: str) -> tuple[list[dict], str]:
    out = subprocess.run(
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
    return json.loads(out.stdout)["findings"], out.stderr


# ---- rendering ---------------------------------------------------------------


def test_rendered_hcl_parses_and_keeps_structure(monkeypatch) -> None:
    # Reads the parse tree itself, so it needs the real parser even in
    # the CI job that forces the regex fallback.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)
    hcl = _render(OPEN_SG)
    tree, err = _hcl.parse_tf(hcl)
    assert err is None
    [body] = _hcl.resource_subtrees(tree)[("aws_security_group", "sg")]
    assert body["ingress"][0]["cidr_blocks"] == ["0.0.0.0/0"]  # nested block
    assert body["tags"] == {"Name": "x"}  # map attribute


def test_labelled_nested_blocks_and_repeated_blocks() -> None:
    hcl = _render(
        {
            "terraform": {"backend": {"s3": {"bucket": "b"}}},
            "resource": [
                {
                    "null_resource": {
                        "a": {
                            "provisioner": [{"local-exec": {"command": "echo"}}],
                            "dynamic": {
                                "setting": {
                                    "for_each": "${var.s}",
                                    "content": {"name": "x"},
                                }
                            },
                        }
                    }
                },
            ],
        }
    )
    assert 'backend "s3" {' in hcl
    assert 'provisioner "local-exec" {' in hcl
    assert 'dynamic "setting" {' in hcl and "content {" in hcl
    assert _hcl.parse_tf(hcl)[1] is None


def test_map_versus_block_heuristics() -> None:
    hcl = _render(
        {
            "resource": {
                "kubernetes_secret": {
                    "s": {
                        "metadata": [{"name": "n"}],  # list of objects: block
                        "data": {".dockerconfigjson": "x"},  # non-identifier key: map
                    }
                }
            }
        }
    )
    assert "metadata {" in hcl
    assert 'data = {\n    ".dockerconfigjson" = "x"' in hcl


def test_single_interpolation_is_emitted_bare_only_when_balanced() -> None:
    hcl = _render(
        {
            "resource": {
                "aws_db_instance": {
                    "d": {
                        "publicly_accessible": "${var.public}",
                        "name": "pre-${var.x}",
                        "odd": "${foo(}",
                    }
                }
            }
        }
    )
    assert "publicly_accessible = var.public" in hcl
    assert 'name = "pre-${var.x}"' in hcl
    assert 'odd = "${foo(}"' in hcl


def test_hostile_keys_and_strings_cannot_inject_structure() -> None:
    hcl = _render(
        {
            "resource": {
                "aws_thing": {
                    'a" {\n} resource "x': {"k": 1},  # bad label: dropped
                    "b": {
                        "bad key = 1 }\nx": 2,  # bad attribute: dropped
                        "s": '"} resource "evil" "e" {',  # stays a string
                    },
                }
            }
        }
    )
    blocks = detect.find_blocks(hcl, detect.RESOURCE_START)
    assert [b["groups"] for b in blocks] == [("aws_thing", "b")]


def test_comment_property_and_unknown_top_level_keys_are_ignored() -> None:
    hcl = _render(
        {"//": "note", "something_else": {"a": 1}, "locals": {"//": "c", "x": 1}}
    )
    assert hcl.split() == ["locals", "{", "x", "=", "1", "}"]


@pytest.mark.parametrize("text", ["[]", "{", '{"a": 1} x', "{" * 1000 + "}" * 1000])
def test_invalid_documents_raise_value_error(text) -> None:
    with pytest.raises(ValueError):
        _tfjson.tf_json_to_hcl(text)


def test_line_map_points_at_json_keys() -> None:
    text = json.dumps(OPEN_SG, indent=2)
    hcl, source = _tfjson.tf_json_to_hcl_with_map(text)
    json_lines = text.splitlines()
    rendered = hcl.splitlines()
    assert len(source) == len(rendered)
    for want in ("sg", "ingress", "cidr_blocks", "Name"):
        [n] = [i for i, ln in enumerate(rendered) if ln.lstrip().startswith(
            (f"{want} ", f'resource "aws_security_group" "{want}"'))]
        assert f'"{want}"' in json_lines[source[n] - 1]


def test_bare_expression_refuses_comments_newlines_and_heredocs() -> None:
    for expr in ("a # c", "a // c", "a /* c */", "a\n", "<<EOT\nx\nEOT\n"):
        hcl = _render({"locals": {"v": "${" + expr + "}"}})
        assert "v = \"" in hcl, expr  # stays a quoted string


# ---- scanning ------------------------------------------------------------------


def test_tf_json_is_scanned_with_json_line_numbers(tmp_path) -> None:
    text = json.dumps(OPEN_SG, indent=2)
    (tmp_path / "main.tf.json").write_text(text)
    findings, _ = _scan(tmp_path)
    [sg] = [f for f in findings if f["id"] == "SEC-AWS-SG-001"]
    assert sg["file"].endswith("main.tf.json")
    assert sg["line"] == next(
        i for i, ln in enumerate(text.splitlines(), 1) if '"sg"' in ln
    )


def test_variables_resolve_across_tf_and_tf_json(tmp_path) -> None:
    (tmp_path / "variables.tf").write_text(
        'variable "public" {\n  type    = bool\n  default = true\n}\n'
    )
    (tmp_path / "main.tf.json").write_text(
        json.dumps(
            {
                "resource": {
                    "aws_db_instance": {"d": {"publicly_accessible": "${var.public}"}}
                }
            }
        )
    )
    ids = {f["id"] for f in _scan(tmp_path)[0]}
    assert "SEC-AWS-RDS-001" in ids


def test_invalid_tf_json_warns_and_rest_is_scanned(tmp_path) -> None:
    (tmp_path / "bad.tf.json").write_text("{ not json")
    (tmp_path / "main.tf.json").write_text(json.dumps(OPEN_SG))
    findings, stderr = _scan(tmp_path)
    assert "bad.tf.json" in stderr
    assert "SEC-AWS-SG-001" in {f["id"] for f in findings}


def test_string_value_cannot_inline_suppress_tf_json(tmp_path) -> None:
    # Rendered line 2 holds the marker; JSON line 2 holds the resource.
    # Read as an inline ignore, it would hide the finding.
    sg = json.dumps(OPEN_SG["resource"])
    (tmp_path / "main.tf.json").write_text(
        '{"locals": {"x": "# tf-analyze:ignore SEC-AWS-SG-001"},\n'
        f'"resource": {sg}}}\n'
    )
    findings, _ = _scan(tmp_path)
    assert [f["line"] for f in findings if f["id"] == "SEC-AWS-SG-001"] == [2]


def test_apply_fixes_leaves_tf_json_alone(tmp_path) -> None:
    path = tmp_path / "main.tf.json"
    path.write_text(json.dumps({"resource": {"aws_db_instance": {"d": {
        "publicly_accessible": True}}}}, indent=2))
    before = path.read_text()
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"),
         "--target", str(tmp_path), "--apply-fixes", "apply"],
        capture_output=True, text=True, check=False,
    )
    assert path.read_text() == before
    assert not (tmp_path / "main.tf.json.bak").exists()


# ---- parity with .tf on real fixtures ------------------------------------------

PARITY_FIXTURES = [
    "aws_alb_tls_1_0",
    "aws_cwl_no_retention",
    "aws_s3_backend_no_lock",
    "provisioner_usage",
    "gcp_compute_oslogin_off",
    "wide_provider_constraint",
    "count_bool_pattern",
    "foreach_keyset_unstable",
]


@pytest.mark.parametrize("name", PARITY_FIXTURES)
def test_fixture_scans_the_same_as_tf_json(tmp_path, name) -> None:
    """Render each fixture's parse tree as Terraform JSON (python-hcl2's
    output is that shape) and require the same findings as the `.tf`."""
    src = REPO / "fixtures" / name
    # Same directory name on both sides: findings name the module by it.
    as_tf, as_json = tmp_path / "tf" / name, tmp_path / "json" / name
    as_tf.mkdir(parents=True)
    as_json.mkdir(parents=True)
    for tf in src.glob("*.tf"):
        (as_tf / tf.name).write_text(tf.read_text())
        doc = _hcl._hcl2.loads(tf.read_text())
        (as_json / f"{tf.name}.json").write_text(json.dumps(doc, indent=2))

    def ids(d: Path) -> set:
        return {
            (f["id"], f.get("resource", ""))
            for f in _scan(d)[0]
            if not f["id"].startswith(("CI-", "STK-DEFAULTS"))
        }

    assert ids(as_json) == ids(as_tf)
