"""Parser migration Step 3 (tasks/hcl-parser-migration.md §4.4–4.6, §9).

Pins: tree values are rendered back to the HCL text catalogue regexes were
written against (`render_hcl`), and that rendering matches today's
`block_arg_value` on every fixture; `resource_arg` / `hcl_attr` read
values top-level, along dotted paths (in `arg` or `nested_path`), from
every instance of a repeated block, on the tree and the regex fallback
alike; `resource_body_contains` ignores comments and heredocs; and plan /
state mode applies the same rules, so static and plan agree.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _hcl  # noqa: E402
import _plan_state  # noqa: E402
import detect  # noqa: E402

CATALOG = detect.load_catalog(REPO_ROOT / "catalog")
ENTRIES = {e["id"]: e for e in CATALOG}


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


@pytest.fixture(params=["tree", "fallback"])
def path_mode(request, monkeypatch):
    if request.param == "fallback":
        monkeypatch.setenv("TF_ANALYZE_TEST_FORCE_FALLBACK", "1")
    return request.param


def _fires(text: str, entry: dict, tmp_path: Path) -> bool:
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    return bool(detect.detect_in_file(fp, text, [entry]))


def _only(rule_id: str, **match) -> dict:
    """The catalogue entry restricted to the one pattern matching `match`."""
    e = ENTRIES[rule_id]
    pats = [p for p in e["patterns"] if all(p.get(k) == v for k, v in match.items())]
    assert len(pats) == 1, (rule_id, match, pats)
    return {**e, "patterns": pats}


# ---- render_hcl / single_interpolation ---------------------------------------

@pytest.mark.parametrize("value, text", [
    ("lit", "lit"),
    ("${var.x}", "var.x"),
    ("pre-${var.x}-post", "pre-${var.x}-post"),
    ("${var.a}-${var.b}", "${var.a}-${var.b}"),
    ("$${literal}", "$${literal}"),
    ('${{for k, v in m : k => "}"}}', '{for k, v in m : k => "}"}'),
    (True, "true"), (False, "false"), (None, "null"), (22, "22"), (-1, "-1"),
    (["0.0.0.0/0", "${var.z}"], '["0.0.0.0/0", var.z]'),
    ({"Name": "n", "k 2": 3, "__start_line__": 1}, '{Name = "n", "k 2" = 3}'),
    ('with "q"', 'with "q"'),
])
def test_render_hcl(value, text) -> None:
    assert _hcl.render_hcl(value) == text


def _norm(s: str | None) -> str | None:
    """Drop whitespace outside strings and trailing commas — layout only."""
    if s is None:
        return None
    out, in_q, prev = [], False, ""
    for ch in s:
        if ch == '"' and prev != "\\":
            in_q = not in_q
        if in_q or not ch.isspace():
            out.append(ch)
        prev = ch
    return re.sub(r",([\]}])", r"\1", "".join(out))


def _value_patterns() -> dict[str, list[tuple[str, str, str]]]:
    out: dict[str, list[tuple[str, str, str]]] = collections.defaultdict(list)
    for e in CATALOG:
        for p in e.get("patterns") or []:
            if p.get("kind") == "resource_arg" and p.get("resource") and p.get("arg"):
                out[p["resource"]].append((e["id"], p["arg"], p.get("nested_path") or p["arg"]))
    return out


def test_render_matches_block_arg_value_on_every_fixture() -> None:
    """Golden test (§4.6): for every `resource_arg` pattern and every
    matching resource in fixtures/ and examples/, the rendered tree value
    equals the text the regex fallback extracts at the same path, up to
    whitespace. (In Step 3 the reference was `block_arg_value(body, arg)`;
    Step 5 made that top-level only, so the comparison is now against
    `block_values_at` on the same path.)"""
    pats = _value_patterns()
    differ, checked = [], 0
    for corpus in ("fixtures", "examples"):
        for tf in sorted((REPO_ROOT / corpus).rglob("*.tf")):
            text = _hcl._read_normalized(tf)
            tree, _ = _hcl.parse_tf(text)
            if tree is None:
                continue
            subtrees = _hcl.resource_subtrees(tree)
            for blk in _hcl.find_blocks(text, detect.RESOURCE_START):
                key = tuple(blk["groups"])
                found = subtrees.get(key, [])
                if len(found) != 1:
                    continue
                attrs = _hcl.normalise_attrs(found[0])
                body = _hcl._expand_dynamic_blocks(blk["body"])
                for rule, arg, path in pats.get(key[0], ()):
                    checked += 1
                    old_vals = _hcl.block_values_at(body, path)
                    old = old_vals[0] if old_vals else None
                    vals = _hcl.attrs_values_at(attrs, path)
                    new = _hcl.render_hcl(vals[0]) if vals else None
                    if _norm(old) == _norm(new):
                        continue
                    differ.append(f"{tf.relative_to(REPO_ROOT)} {'.'.join(key)} {rule} {path}: "
                                  f"old={old!r} new={new!r}")
    assert checked > 500
    assert not differ, "\n".join(differ[:20])


# ---- resource_arg / hcl_attr value semantics, both paths ---------------------

DOTTED = [
    ("ROB-AWS-S3-001", "aws_s3_bucket_versioning",
     "versioning_configuration {\n    status = \"%s\"\n  }", "Suspended", "Enabled"),
    ("ROB-AZURE-STORAGE-001", "azurerm_storage_account",
     "blob_properties {\n    delete_retention_policy {\n      days = %s\n    }\n  }", "3", "30"),
    ("SEC-AWS-SSRF-001", "aws_instance",
     "metadata_options {\n    http_tokens = \"%s\"\n  }", "optional", "required"),
    ("STK-AZURE-FUNCTION-001", "azurerm_linux_function_app",
     "site_config {\n    application_stack {\n      python_version = \"%s\"\n    }\n  }", "3.7", "3.12"),
    ("STK-GCP-FUNCTIONS-001", "google_cloudfunctions2_function",
     "build_config {\n    runtime = \"%s\"\n  }", "python38", "python312"),
]


@pytest.mark.parametrize("rule, rtype, body, bad, good", DOTTED, ids=[d[0] for d in DOTTED])
def test_dotted_arg_patterns_fire(rule, rtype, body, bad, good, tmp_path, path_mode) -> None:
    """These `resource_arg` patterns put a dotted path in `arg`. The old
    lookup searched for a line starting `a.b.c =`, so they never fired;
    they now walk the path. Run with only that pattern enabled."""
    arg = next(p["arg"] for p in ENTRIES[rule]["patterns"]
               if p.get("kind") == "resource_arg" and p.get("resource") == rtype)
    entry = _only(rule, kind="resource_arg", resource=rtype, arg=arg)
    text = f'resource "{rtype}" "x" {{\n  {body}\n}}\n'
    assert _fires(text % bad, entry, tmp_path)
    assert not _fires(text % good, entry, tmp_path)


def test_msk_plaintext_fires_via_nested_path(tmp_path, path_mode) -> None:
    entry = _only("SEC-AWS-MSK-001", kind="resource_arg")
    fx = REPO_ROOT / "fixtures" / "aws_msk_plaintext" / "main.tf"
    text = fx.read_text()
    assert _fires(text, entry, tmp_path)
    assert not _fires(text.replace('"PLAINTEXT"', '"TLS"').replace('"TLS_PLAINTEXT"', '"TLS"'),
                      entry, tmp_path)


def _arg_entry(path: str, **extra) -> dict:
    pat = {"kind": "resource_arg", "resource": "aws_thing", "arg": path, **extra}
    return {"id": "TEST-STEP3-001", "default_urgency": "LOW", "patterns": [pat]}


REPEATED = (
    'resource "aws_thing" "a" {\n'
    '  rule {\n'
    '    mode = "safe"\n'
    '  }\n'
    '  rule {\n'
    '    mode = "open"\n'
    '  }\n'
    '  rule {\n'
    '    name = "no-mode"\n'
    '  }\n'
    '}\n'
)


def test_resource_arg_any_instance_matches(tmp_path, path_mode) -> None:
    assert _fires(REPEATED, _arg_entry("rule.mode", regex="^open$"), tmp_path)
    assert not _fires(REPEATED, _arg_entry("rule.mode", regex="^bogus$"), tmp_path)


def test_fire_if_absent_when_any_instance_lacks_it(tmp_path, path_mode) -> None:
    assert _fires(REPEATED, _arg_entry("rule.mode", regex="^bogus$", fire_if_absent=True), tmp_path)


def test_resource_arg_value_is_top_level(tmp_path, path_mode) -> None:
    text = (
        'resource "aws_thing" "a" {\n'
        '  logging {\n'
        '    mode = "open"\n'
        '  }\n'
        '}\n'
    )
    assert not _fires(text, _arg_entry("mode", regex="^open$"), tmp_path)
    assert _fires(text, _arg_entry("logging.mode", regex="^open$"), tmp_path)


def test_resource_arg_value_renders_bools_lowercase(tmp_path, path_mode) -> None:
    text = 'resource "aws_thing" "a" {\n  enabled = false\n}\n'
    assert _fires(text, _arg_entry("enabled", regex="^false$"), tmp_path)


def test_hcl_attr_any_instance_differs(tmp_path, path_mode) -> None:
    entry = {"id": "TEST-STEP3-002", "default_urgency": "LOW", "patterns": [
        {"kind": "hcl_attr", "resource": "aws_thing", "path": "rule.mode", "not_equal": "safe"}]}
    assert _fires(REPEATED, entry, tmp_path)
    only_safe = REPEATED.replace('"open"', '"safe"')
    assert not _fires(only_safe, entry, tmp_path)


# ---- resource_body_contains ignores comments and heredocs --------------------

def test_body_contains_ignores_comments_and_heredocs(tmp_path, path_mode) -> None:
    entry = _only("SEC-AWS-CLOUDFRONT-001", kind="resource_body_contains")
    base = 'resource "aws_cloudfront_distribution" "d" {\n%s\n}\n'
    assert _fires(base % '  viewer_protocol_policy = "allow-all"', entry, tmp_path)
    assert not _fires(base % '  # viewer_protocol_policy = "allow-all"', entry, tmp_path)
    assert not _fires(base % '  comment = <<EOT\nviewer_protocol_policy = "allow-all"\nEOT', entry, tmp_path)
    # A `#` inside a string is not a comment.
    assert _fires(base % '  x = "a#b"\n  viewer_protocol_policy = "allow-all"', entry, tmp_path)


# ---- plan / state mode uses the same rules ------------------------------------

def _plan_fires(values: dict, entry: dict, rtype: str = "aws_thing") -> bool:
    return bool(_plan_state.evaluate_against_resources(
        [{"type": rtype, "address": f"{rtype}.a", "values": values}], [entry],
        finding_mode="plan", file_marker="plan",
    ))


def test_plan_renders_bools_and_lists_like_static() -> None:
    assert _plan_fires({"enabled": False}, _arg_entry("enabled", regex="^false$"))
    assert _plan_fires({"cidrs": ["0.0.0.0/0"]}, _arg_entry("cidrs", regex=r'\["0\.0\.0\.0/0"\]'))


def test_plan_walks_dotted_arg_and_prefers_nested_path() -> None:
    values = {"metadata_options": [{"http_tokens": "optional"}]}
    assert _plan_fires(values, _arg_entry("metadata_options.http_tokens", regex="^optional$"))
    missing = {"id": "T", "patterns": [{"kind": "resource_missing_arg", "resource": "aws_thing",
                                        "arg": "leaf", "nested_path": "outer.leaf"}]}
    assert not _plan_fires({"outer": [{"leaf": 1}]}, missing)


def test_plan_missing_arg_every_instance_and_empty_values() -> None:
    entry = {"id": "T", "patterns": [{"kind": "resource_missing_arg", "resource": "aws_thing",
                                      "nested_path": "rule.mode"}]}
    assert _plan_fires({"rule": [{"mode": "a"}, {"mode": None}]}, entry)
    assert not _plan_fires({"rule": [{"mode": "a"}, {"mode": "b"}]}, entry)
    assert _plan_fires({"rule": []}, entry)
    any_entry = {"id": "T", "patterns": [{**entry["patterns"][0], "instances": "any"}]}
    assert not _plan_fires({"rule": [{"mode": "a"}, {"mode": None}]}, any_entry)


def _strip_meta(v):
    if isinstance(v, dict):
        return {k: _strip_meta(x) for k, x in v.items()
                if not (k.startswith("__") and k.endswith("__"))}
    if isinstance(v, list):
        return [_strip_meta(x) for x in v]
    return v


def test_static_and_plan_agree_on_every_fixture() -> None:
    """For every fixture/example resource whose values are all literals,
    the plan values Terraform would produce are the parsed settings
    themselves. Every plan-supported pattern for that resource type must
    then decide the same way statically and in plan mode (§9)."""
    by_type: dict[str, list[dict]] = collections.defaultdict(list)
    for e in CATALOG:
        for p in e.get("patterns") or []:
            # Skipped: patterns that depend on other resources or raw text
            # (one resource at a time cannot model them; plan-mode
            # companions are tested in test_s3_split_resources.py).
            if (p.get("kind") in ("resource_arg", "resource_missing_arg", "hcl_attr")
                    and p.get("resource") and not p.get("suppress_if_body_contains")
                    and not p.get("unless_companion")):
                by_type[p["resource"]].append({**e, "patterns": [p]})
    checked, disagreements = 0, []
    for corpus in ("fixtures", "examples"):
        for tf in sorted((REPO_ROOT / corpus).rglob("*.tf")):
            text = _hcl._read_normalized(tf)
            tree, _ = _hcl.parse_tf(text)
            if tree is None:
                continue
            subtrees = _hcl.resource_subtrees(tree)
            for blk in _hcl.find_blocks(text, detect.RESOURCE_START):
                key = tuple(blk["groups"])
                found = subtrees.get(key, [])
                if len(found) != 1 or key[0] not in by_type:
                    continue
                values = _strip_meta(_hcl.normalise_attrs(found[0]))
                if "${" in json.dumps(values) or "count" in values or "for_each" in values:
                    continue
                addr = ".".join(key)
                for entry in by_type[key[0]]:
                    checked += 1
                    static = any(f["resource"] == addr
                                 for f in detect.detect_in_file(tf, text, [entry]))
                    plan = _plan_fires(values, entry, key[0])
                    if static != plan:
                        p = entry["patterns"][0]
                        disagreements.append(
                            f"{tf.relative_to(REPO_ROOT)} {addr} {entry['id']} {p['kind']} "
                            f"{p.get('nested_path') or p.get('arg') or p.get('path')}: "
                            f"static={static} plan={plan}")
    assert checked > 1000
    assert not disagreements, "\n".join(disagreements[:20])
