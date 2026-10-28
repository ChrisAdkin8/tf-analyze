"""Values from the scanned repository (file paths, resource names) stay
inert in Markdown output: a crafted file name must not break out of its
code span or table cell in a PR comment (critical review)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from _attack_graph import _mermaid_label
from _output import _md_code

REPO = Path(__file__).resolve().parents[1]
PAYLOAD = "a` | ![x](https://e.vil/x.png) @octocat `"
# A file name cannot contain "/", so the image URL is relative.
FILE_PAYLOAD = "a` | ![x](evil.png) @octocat `"

SSH_OPEN = """resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def _cells(row: str) -> list[str]:
    """Table cells split on unescaped `|` (GitHub's rule, code spans too)."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", row.strip())[1:-1]]


def _is_one_code_span(cell: str) -> bool:
    m = re.fullmatch(r"(`+)(.*)\1", cell, re.DOTALL)
    if not m:
        return False
    fence, inner = m.groups()
    return all(len(run) != len(fence) for run in re.findall(r"`+", inner))


def test_md_code_contains_any_value() -> None:
    for value in ("main.tf:3", PAYLOAD, "`x`", "a|b", "``", "line\nbreak"):
        span = _md_code(value)
        assert _is_one_code_span(span), span
        assert "\n" not in span
        assert len(_cells(f"| {span} |")) == 1, span


def test_pr_summary_keeps_a_hostile_file_name_inert(tmp_path) -> None:
    (tmp_path / f"{FILE_PAYLOAD}.tf").write_text(SSH_OPEN)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "pr-summary",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    rows = [ln for ln in out.splitlines() if "evil.png" in ln]
    assert rows, out
    for row in rows:
        cells = _cells(row)
        assert len(cells) == 3, row  # Urgency | Rule | Location
        assert _is_one_code_span(cells[2]), row


def test_pr_summary_shows_the_escalated_urgency(tmp_path) -> None:
    (tmp_path / "main.tf").write_text(SSH_OPEN)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "pr-summary",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    row = next(
        ln for ln in out.splitlines() if "SEC-AWS-SG-001" in ln and ln.startswith("|")
    )
    assert "**CRITICAL**" in row, row  # escalated from the catalogue's HIGH


def test_fleet_report_escapes_targets_and_resource_names() -> None:
    from _modes import render_fleet_report

    finding = {"id": "R-1", "resource": f"aws_s3_bucket.{PAYLOAD}", "file": "main.tf"}
    result = {
        "by_target": {f"/repos/{PAYLOAD}": [finding]},
        "fleet_wide": [{**finding, "fleet_count": 2, "fleet_repos": ["a", "b"]}],
        "summary": {f"/repos/{PAYLOAD}": 1},
    }
    out = render_fleet_report(result, "text")
    rows = [ln for ln in out.splitlines() if ln.startswith("|") and "e.vil" in ln]
    assert len(rows) >= 2, out  # the per-repo summary and the fleet-wide table
    for row in rows:
        assert any(_is_one_code_span(c) and "e.vil" in c for c in _cells(row)), row
        assert not any("e.vil" in c and not _is_one_code_span(c) for c in _cells(row)), row


def test_mermaid_labels_cannot_carry_html_or_end_the_fence() -> None:
    label = _mermaid_label('x"<img src=x onerror=alert(1)>\n```')
    assert (
        "<" not in label and ">" not in label and "\n" not in label and '"' not in label
    )


# ---------------------------------------------------------------------------
# Catalogue text: a custom rule in the scanned repo's rules_dir supplies its
# own title and fix_hcl, and the bot posts them in PR comments.
# ---------------------------------------------------------------------------

HOSTILE_TITLE = (
    "x](https://e.vil) ![i](http://e.vil/i.png) <img src=x> @octocat www.e.vil"
)
HOSTILE_FIX = 'x = 1\n```\n\n## All checks passed - safe to merge\n[click](https://e.vil)\n```'


def _unsafe(text: str) -> list[str]:
    """Constructs that would render as something other than plain text."""
    prose = re.sub(r"(`+).+?(?<!`)\1(?!`)", "", text)
    problems = []
    if re.search(r"(?<!\\)[\[<]", prose):
        problems.append("link/image/html")
    if re.search(r"@\w", prose):
        problems.append("mention")
    if re.search(r"(?i)https?://|\bwww\.", prose):
        problems.append("autolink")
    if re.match(r"\s*#", prose):
        problems.append("heading")
    return problems


def test_md_text_neutralises_markup_outside_code_spans() -> None:
    from _output import _md_text

    for title in (HOSTILE_TITLE, "## heading", r"\[x](y)", "a\n# b"):
        out = _md_text(title)
        assert not _unsafe(out), (title, out)
        assert "\n" not in out
    built_in = "Missing `deletion_protection` on `aws_db_instance`"
    assert _md_text(built_in) == built_in
    # Text inside a code span is literal in Markdown, so it is left alone.
    assert _md_text("`[a](b) @c`") == "`[a](b) @c`"
    # A span can't start inside a backtick run: "``" opens a span only if
    # "``" closes it, so here the link is prose and must be escaped.
    tricky = "``[a](https://e.vil)`"
    assert _md_text(tricky) == "``\\[a\\](https:\u200b//e.vil)`"


def test_md_fence_cannot_be_closed_by_its_body() -> None:
    from _output import _md_fence

    opener, body, closer = _md_fence(HOSTILE_FIX, "suggestion")
    assert opener == closer + "suggestion" and body == HOSTILE_FIX
    # CommonMark: a closing fence needs at least as many backticks.
    assert all(len(run) < len(closer) for run in re.findall(r"`+", body))
    assert _md_fence("x = 1", "hcl") == ["```hcl", "x = 1", "```"]


def _hostile_rule_repo(tmp_path: Path) -> Path:
    """SEC-AWS-SG-001 copied into a rules_dir with a hostile title and fix_hcl
    (text edits: the engine's YAML reader wants the catalogue's own style)."""
    text = (REPO / "catalog" / "SEC-AWS-SG-001.yaml").read_text()
    head, rest = text.split("fix_hcl: |\n", 1)
    tail = rest[rest.index("fix_disruption:"):]
    fix = "".join(f"  {line}\n" if line else "\n" for line in HOSTILE_FIX.splitlines())
    text = head + "fix_hcl: |\n" + fix + tail
    text = text.replace("id: SEC-AWS-SG-001", "id: CUSTOM-EVIL-001", 1)
    text = text.replace('title: "Security group allows ingress from 0.0.0.0/0"',
                        f"title: {json.dumps(HOSTILE_TITLE)}", 1)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "CUSTOM-EVIL-001.yaml").write_text(text)
    (tmp_path / ".tf-analyze.yaml").write_text("rules_dir: rules\n")
    (tmp_path / "main.tf").write_text(SSH_OPEN)
    return tmp_path


def test_pr_summary_keeps_a_hostile_custom_rule_inert(tmp_path) -> None:
    target = _hostile_rule_repo(tmp_path)
    out = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "detect.py"), "--target", str(target),
         "--format", "pr-summary"],
        capture_output=True, text=True, check=False,
    ).stdout
    assert "CUSTOM-EVIL-001" in out, out
    row = next(line for line in out.splitlines() if "CUSTOM-EVIL-001" in line and line.startswith("|"))
    title_cell = _cells(row)[1].split(" — ", 1)[1]
    assert not _unsafe(title_cell), title_cell
    # The fix block holds the whole fix_hcl: the injected heading stays inside it.
    lines = out.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("```") and line.endswith("hcl"))
    fence = lines[start][: -len("hcl")]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == fence)
    assert "## All checks passed - safe to merge" in lines[start:end]
    assert "## All checks passed - safe to merge" not in lines[end:]


def test_action_comment_escaping_matches_the_engine() -> None:
    """action.yml's JS mdText / fence give the same output as _md_text / _md_fence."""
    import shutil

    pytest = __import__("pytest")
    yaml = pytest.importorskip("yaml")
    if not shutil.which("node"):
        pytest.skip("node not installed")
    from _output import _md_fence, _md_text

    action = yaml.safe_load((REPO / "action.yml").read_text())
    script = next(s["with"]["script"] for s in action["runs"]["steps"]
                  if "mdText" in (s.get("with") or {}).get("script", ""))
    helpers = "\n".join(
        line for line in script.splitlines()
        if line.lstrip().startswith(("const mdText", "const t =", "const esc", ".replace(", "let out",
                                     "for (const m of t.matchAll", "out +=", "last = m", "}", "return (out",
                                     "};", "const fence"))
    )
    start = helpers.index("const mdText")
    end = helpers.index("\n", helpers.index("const fence")) if "\n" in helpers[helpers.index("const fence"):] else len(helpers)
    js = helpers[start:end]
    samples = [HOSTILE_TITLE, "## heading", r"\[x](y)", "`[a](b) @c` and [d]", "Missing `x` on `y`",
               "``[a](https://e.vil)`", "``x`[a](b)`"]
    prog = js + "\nconst S = " + json.dumps(samples) + ";\n" + \
        "console.log(JSON.stringify({t: S.map(mdText), f: fence(" + json.dumps(HOSTILE_FIX) + ")}));"
    out = json.loads(subprocess.run(["node", "-e", prog], capture_output=True, text=True, check=True).stdout)
    assert out["t"] == [_md_text(s) for s in samples]
    assert out["f"] == _md_fence(HOSTILE_FIX)[2]


def test_custom_rule_id_must_be_plain(tmp_path) -> None:
    """The id is printed in comments as-is, so only A-Z, 0-9 and dashes."""
    from _catalog import validate_catalog_entry

    assert not [e for e in validate_catalog_entry({"id": "CUSTOM-ACME-001"}, "x/CUSTOM-ACME-001.yaml")
                if "upper-case" in e]
    for bad in ("CUSTOM-[x](https:", "CUSTOM-<img>", "CUSTOM-a", "custom-x-1", "CUSTOM"):
        errs = validate_catalog_entry({"id": bad}, f"x/{bad}.yaml")
        assert any("upper-case" in e for e in errs), bad
