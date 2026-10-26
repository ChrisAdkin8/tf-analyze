"""Block discovery (`_hcl._block_index` / `find_blocks`).

Blocks are found by one lexer pass that knows strings, templates,
comments and heredocs. Each case here used to be a silent false negative
(or a wrong line) with the old `^\\s*resource\\s+"…"` header regex.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import _hcl
import detect

REPO = Path(__file__).resolve().parents[1]

OPEN_SG = (
    'resource "aws_security_group" "sg" {\n'
    "  ingress {\n"
    "    from_port   = 22\n"
    "    to_port     = 22\n"
    '    protocol    = "tcp"\n'
    '    cidr_blocks = ["0.0.0.0/0"]\n'
    "  }\n"
    "}\n"
)


def _resources(text: str) -> list[tuple]:
    return [
        (b["groups"], b["start_line"])
        for b in detect.find_blocks(text, detect.RESOURCE_START)
    ]


def _scan(tmp_path: Path, text: str) -> list[dict]:
    (tmp_path / "main.tf").write_text(text)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return json.loads(out.stdout)["findings"]


# ---- what is (not) a block ---------------------------------------------------


def test_heredoc_comment_char_does_not_swallow_block_end() -> None:
    text = (
        'resource "aws_instance" "a" {\n'
        "  user_data = <<-EOT\n"
        "    X=$${HOSTNAME#ip-}\n"
        '    echo "// not a comment {"\n'
        "  EOT\n"
        "}\n"
        'resource "aws_instance" "b" {\n'
        "}\n"
    )
    assert _resources(text) == [(("aws_instance", "a"), 1), (("aws_instance", "b"), 7)]


def test_block_comment_and_heredoc_headers_are_not_blocks() -> None:
    text = (
        "/*\n"
        'resource "aws_db_instance" "old" {\n'
        "}\n"
        "*/\n"
        'resource "aws_thing" "a" {\n'
        "  doc = <<EOT\n"
        'resource "aws_db_instance" "fake" {\n'
        "}\n"
        "EOT\n"
        "}\n"
    )
    assert _resources(text) == [(("aws_thing", "a"), 5)]


def test_unquoted_labels_and_comment_in_header() -> None:
    text = (
        'resource aws_thing a {\n}\nresource /* { */ "aws_thing" # note\n  "b" {\n}\n'
    )
    # A newline between labels is not valid HCL, so only `a` is a block.
    assert _resources(text) == [(("aws_thing", "a"), 1)]
    text = 'resource /* { */ "aws_thing" "b" {\n  x = 1\n}\n'
    [blk] = detect.find_blocks(text, detect.RESOURCE_START)
    assert blk["groups"] == ("aws_thing", "b") and blk["body"] == "\n  x = 1\n"


def test_start_line_ignores_preceding_blank_lines() -> None:
    assert _resources('\n\n\n\nresource "aws_thing" "a" {\n}\n') == [
        (("aws_thing", "a"), 5)
    ]


def test_templates_and_escapes_inside_strings() -> None:
    text = (
        'resource "aws_thing" "a" {\n'
        '  a = "${ {k = "}"}["k"] }"\n'
        '  b = "$${literal} %%{literal} \\" }"\n'
        '  c = "%{ if true }}{%{ endif }"\n'
        "}\n"
        'resource "aws_thing" "b" {\n}\n'
    )
    assert _resources(text) == [(("aws_thing", "a"), 1), (("aws_thing", "b"), 6)]


def test_attribute_object_is_not_a_block() -> None:
    assert detect.find_blocks("x = {\n}\n", re.compile(r"x\s*\{")) == []


def test_label_count_and_kind_come_from_the_regex() -> None:
    text = 'data "aws_ami" "a" {\n}\nmodule "m" {\n}\nlocals {\n}\n'
    assert [b["groups"] for b in detect.find_blocks(text, detect.DATA_START)] == [
        ("aws_ami", "a")
    ]
    assert [b["groups"] for b in detect.find_blocks(text, detect.MODULE_START)] == [
        ("m",)
    ]
    assert len(detect.find_blocks(text, detect.LOCALS_START)) == 1
    assert _resources(text) == []


# ---- unbalanced input ----------------------------------------------------------


def test_unclosed_block_does_not_hide_later_blocks() -> None:
    text = 'resource "aws_thing" "broken" {\n  x = 1\nresource "aws_thing" "ok" {\n}\n'
    assert _resources(text) == [(("aws_thing", "ok"), 3)]


def test_many_unclosed_headers_are_linear() -> None:
    text = 'resource "aws_s3_bucket" "b" {\n' * 20000
    t0 = time.perf_counter()
    assert _resources(text) == []
    assert time.perf_counter() - t0 < 5  # quadratic took minutes at 3000


def test_hostile_unclosed_constructs_are_linear_and_recover() -> None:
    later = 'resource "aws_thing" "a" {\n}\n'
    for broken in (
        'x = "' + '${"' * 5000 + "\n",  # deep nesting: no RecursionError
        "x = <<EOT\n" * 5000,           # back-to-back unterminated heredocs
        "/*\n" * 5000,                  # unterminated block comments
        'x = "${ {\n' * 5000,           # unclosed templates
    ):
        t0 = time.perf_counter()
        assert [g for g, _ in _resources(broken + later)] == [("aws_thing", "a")]
        assert time.perf_counter() - t0 < 5


def test_brace_walk_many_unterminated_heredocs_is_linear() -> None:
    t0 = time.perf_counter()
    _hcl.brace_walk("{ x = <<A\n" * 5000 + "}")
    assert time.perf_counter() - t0 < 5


def test_brace_walk_skips_heredoc_body() -> None:
    body = "{\n  s = <<EOT\n# }\n}\nEOT\n  y = 1\n}\ntail"
    assert body[: _hcl.brace_walk(body)].endswith("y = 1\n}")


def test_comment_inside_template_does_not_move_depth() -> None:
    text = (
        "locals {\n"
        '  x = "${ 1 /* {{{ */ }"\n'
        '  y = "${ 2 # { \n }"\n'
        "}\n"
        'resource "aws_thing" "a" {\n'
        "}\n"
    )
    assert _resources(text) == [(("aws_thing", "a"), 6)]


def test_runaway_constructs_cost_at_most_their_line() -> None:
    later = 'resource "aws_thing" "a" {\n}\n'
    for broken in (
        'x = "${ {{ \n',        # template that never closes
        "/* never closed\n",    # block comment that never closes
        "x = <<EOT\nbody\n",   # heredoc with no terminator
    ):
        text = broken + later
        assert [g for g, _ in _resources(text)] == [("aws_thing", "a")], broken


# ---- end to end, on the real catalogue -----------------------------------------


def test_commented_out_copy_does_not_hide_real_finding(tmp_path) -> None:
    text = "/*\n" + OPEN_SG + "*/\n" + OPEN_SG
    found = [f for f in _scan(tmp_path, text) if f["id"] == "SEC-AWS-SG-001"]
    assert [f["line"] for f in found] == [OPEN_SG.count("\n") + 3]


def test_inline_ignore_after_blank_line_applies(tmp_path) -> None:
    text = (
        "\n"
        'resource "aws_db_instance" "a" { # tf-analyze:ignore SEC-AWS-RDS-001\n'
        "  publicly_accessible = true\n"
        "}\n"
    )
    assert "SEC-AWS-RDS-001" not in {f["id"] for f in _scan(tmp_path, text)}
