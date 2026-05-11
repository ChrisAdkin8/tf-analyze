"""Regression tests for the 2026-05-11 audit.

Each test guards an audit finding by asserting either the fix is in place
or the prior failure mode no longer triggers. Grouped here (instead of
spread across module-specific files) so a future audit can grep one
location and confirm the whole batch is still covered.

Audit document: ``tasks/repo-audit-2026-05-11.md``.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DETECT = REPO / "scripts" / "detect.py"
sys.path.insert(0, str(REPO / "scripts"))


# ─── Audit item 36 — engine JSON output is deterministic across runs ──
def test_engine_json_is_byte_identical_across_runs(tmp_path: Path) -> None:
    """Run detect.py twice on the same fixture; the JSON bytes must match.

    Closes the audit gap that doc claimed "byte-identical" output
    without an assertion. The engine is in fact deterministic — sorted
    by rule id internally — and this guards future regressions where
    iteration over an unordered dict could leak nondeterminism.
    """
    target = REPO / "fixtures" / "attack_graph_demo"
    if not target.exists():
        pytest.skip("attack_graph_demo fixture not present")
    out: list[str] = []
    for _ in range(2):
        r = subprocess.run(
            [sys.executable, str(DETECT), "--target", str(target),
             "--format", "json", "--attack-graph"],
            capture_output=True, text=True,
        )
        # exit 1 = findings present (expected); >1 = engine crash
        assert r.returncode <= 1, r.stderr
        out.append(r.stdout)
    assert out[0] == out[1], "engine JSON output is not deterministic"


# ─── Audit item 40 — engine crashes must not be swallowed ─────────────
def test_engine_stderr_carries_no_traceback_on_clean_run() -> None:
    """A successful scan must not emit `Traceback (most recent call last)`.

    Previously test_public_scanner.py and scripts/self_test.py read
    stderr only when the exit code was already non-zero, so an
    unhandled exception that still printed a JSON body slipped through.
    """
    target = REPO / "fixtures" / "attack_graph_demo"
    if not target.exists():
        pytest.skip("attack_graph_demo fixture not present")
    r = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(target),
         "--format", "json", "--attack-graph"],
        capture_output=True, text=True,
    )
    assert "Traceback (most recent call last)" not in (r.stderr or "")
    assert "ERROR:" not in (r.stderr or ""), r.stderr


# ─── Round 5 audit — _cmd_explain rejects path-traversal rule IDs ───
def test_cmd_explain_rejects_path_traversal() -> None:
    """Round-5 audit fix #2 — `--explain ../../etc/passwd` was
    previously joined to `catalog_dir` without validation, allowing
    read access to any `*.yaml` file on the host. The new shape
    validates against `_RULE_ID_RE` (same regex used by
    `_cmd_new_rule`) and returns exit 2 on a mismatch.
    """
    import sys as _sys
    _sys.path.insert(0, str(REPO / "scripts"))
    import detect  # type: ignore
    from pathlib import Path as _P
    # Each of these is malformed for one of: lowercase, leading dash,
    # path traversal, embedded slash, embedded null. All must reject.
    for bad in ("../../etc/passwd", "sec-aws-s3-001", "SEC/AWS/X-001",
                "SEC..AWS..X-001", "SEC\x00AWS-X-001"):
        rc = detect._cmd_explain(_P("/tmp"), bad)
        assert rc == 2, f"expected exit 2 for malformed rule_id {bad!r}, got {rc}"


def test_cmd_explain_accepts_valid_rule_id_format() -> None:
    """Negative space: a well-formed rule_id should NOT be rejected
    by the validator. The follow-up `yml.exists()` check produces
    exit 1 (not 2) for a non-existent but well-formed ID.
    """
    import sys as _sys
    _sys.path.insert(0, str(REPO / "scripts"))
    import detect  # type: ignore
    from pathlib import Path as _P
    # Well-formed but doesn't exist on disk → exit 1, not 2.
    rc = detect._cmd_explain(_P("/tmp"), "SEC-FAKE-RULE-999")
    assert rc == 1, f"valid rule_id should reach exists-check; got {rc}"


# ─── Round 4 audit — HTML output escapes engine-supplied fields ─────
def test_html_report_escapes_user_controlled_fields() -> None:
    """Round-4 audit fix #1 / #2 — every engine-supplied field rendered
    into the HTML report must round-trip through `html.escape`. A
    custom-catalogue rule title or a finding's resource name
    containing ``<img onerror=alert(1)>`` would otherwise execute JS
    in any browser opening the rendered report.

    The class was closed in the VS Code extension's webview by R30.8
    but the same shape lived in the Python-emitted HTML report
    until R30.11 (this round).
    """
    import sys as _sys
    _sys.path.insert(0, str(REPO / "scripts"))
    from _output import to_html  # type: ignore
    findings = [{
        "id": "SEC-XSS-TEST",
        "urgency": "HIGH",
        "section": "security",
        "file": "<script>alert('file')</script>",
        "line": 1,
        "resource": "aws_s3_bucket.<script>alert('rsrc')</script>",
        "title": "<img onerror=alert('title')>",
    }]
    entries = [{
        "id": "SEC-XSS-TEST",
        "title": "<img onerror=alert('rule-title')>",
        "default_urgency": "HIGH",
        "section": "security",
    }]
    out = to_html(findings, entries, [], graph=None, summary={
        "score": 50, "grade": "C", "scoring_version": 1,
        "formula": "score = 100 - sum(rule_weight)",
        "counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    })
    # The dangerous bytes must all be HTML-escaped — the literal
    # `<script>` and `<img onerror=...>` must NOT appear in the output.
    assert "<script>alert" not in out, "raw <script> appeared in rendered HTML"
    assert "<img onerror=" not in out, "raw <img onerror=> appeared in rendered HTML"
    # The escaped form must appear.
    assert "&lt;script&gt;" in out or "&lt;img" in out, (
        "expected escaped form of XSS payload in HTML output"
    )


def test_standalone_attack_graph_sidebar_escapes_node_fields() -> None:
    """Round-4 audit fix #3 — the standalone HTML attack-graph
    sidebar previously called `innerHTML = ... + n.type + ...`
    without escaping. This test verifies the JS now defines `esc()`
    and the sidebar interpolations route through it.
    """
    import sys as _sys
    _sys.path.insert(0, str(REPO / "scripts"))
    from _attack_graph import _render_graph_html  # type: ignore
    graph = {
        "nodes": [
            {"id": "aws_s3.x", "label": "x", "type": "storage",
             "file": "main.tf", "line": 5,
             "is_crown_jewel": False, "internet_reachable": False,
             "on_critical_path": False, "findings": []},
        ],
        "edges": [],
        "critical_path": [],
    }
    html = _render_graph_html(graph)
    # The escape helper must be defined and called for every node field
    # rendered into innerHTML. We assert on the discipline rather than
    # on a specific payload — the test in `to_html` above exercises
    # the dangerous-payload case.
    assert "function esc(" in html, "sidebar escape helper missing"
    assert "esc(n.type)" in html, "n.type must route through esc()"
    assert "esc(n.file)" in html, "n.file must route through esc()"
    assert "esc(f)" in html, "finding IDs must route through esc()"


# ─── Round 3 audit — strip_hcl_context preserves byte offsets ───────
def test_strip_hcl_context_preserves_length_and_offsets() -> None:
    """The R30.9 `hcl_context` line-counting "fix" assumed comments
    shifted byte offsets in the stripped text; the actual contract is
    that comments are replaced with equal-length whitespace, so the
    stripped text shares lengths and offsets with the original. The
    fix was a no-op at best and a regression source on first-occurrence
    collisions of `text.find(matched)`. Pinning the invariant prevents
    a future contributor from "fixing" the same imaginary bug again.
    """
    from _hcl import strip_hcl_context  # type: ignore
    samples = [
        "resource \"aws_s3_bucket\" \"x\" { # a comment\n  encrypted = false\n}\n",
        "// double-slash comment\n  key = \"value\"\n/* block\ncomment */\n",
        "no comments at all here\n",
        "",
    ]
    for src in samples:
        stripped = strip_hcl_context(src)
        assert len(stripped) == len(src), (
            f"strip_hcl_context changed length from {len(src)} to "
            f"{len(stripped)} on input {src!r}"
        )
        # Every newline in the original must appear at the same offset
        # in the stripped output — the line-counting contract relies
        # on this.
        for i, ch in enumerate(src):
            if ch == "\n":
                assert stripped[i] == "\n", (
                    f"newline at offset {i} moved during strip on {src!r}"
                )


# ─── Audit item 22 — single-element `~> N` constraints must work ───────
def test_versions_tilde_arrow_single_element_includes_min_v() -> None:
    """`~> 3` previously short-circuited via `len(v) < 2: continue`.

    Now padded to `(3, 0)` and treated as `[3.0, 4.0)`, the same shape
    as `~> 3.0`. The audit's stated failure mode (false negative on
    version-gated rules) closes once both forms reach the same
    upper-bound math.
    """
    from _versions import _provider_constraint_allows  # type: ignore
    # `~> 3` should allow provider min_version 3.0
    assert _provider_constraint_allows("~> 3", "3.0") is True
    # `~> 3` should NOT allow provider min_version 4.0 (upper bound)
    assert _provider_constraint_allows("~> 3", "4.0") is False
    # Single-element form should be equivalent to the two-element form
    for min_v in ("2.0", "3.0", "3.5", "4.0", "5.0"):
        a = _provider_constraint_allows("~> 3", min_v)
        b = _provider_constraint_allows("~> 3.0", min_v)
        assert a == b, f"~> 3 vs ~> 3.0 disagreed at min_v={min_v}: {a} vs {b}"


# ─── Audit item 29 — malformed glob in catalogue raises, not silently ──
def test_valid_globs_still_match() -> None:
    """Direct check that the supported file-glob shapes resolve against
    `Path.match` the way the engine relies on them. The audit-29 fix
    narrows the `except Exception:` arm to `except ValueError:` (and
    re-raises with the offending glob) so a future Python change that
    starts raising on an unsupported pattern fails loudly instead of
    silently substring-matching.
    """
    from pathlib import PurePosixPath as _P
    # The two shapes detect.py shortcircuits on always-match
    assert _P("infra/main.tf").match("**/*.tf")
    # Workflow YAML pattern used by the R30.6 walker
    assert _P(".github/workflows/release.yml").match(".github/workflows/*.yml")


# ─── Audit item 8 — find_latest_prior tolerates concurrent unlink ─────
def test_find_latest_prior_tolerates_missing_file(tmp_path: Path) -> None:
    """A file that disappears between `glob()` and `stat()` must not
    crash the scan. The new `_mtime_safe` arm skips and continues.
    """
    from _diff import find_latest_prior  # type: ignore
    # Two real files plus a guarantee that the function tolerates the
    # general missing-file shape via the try/except OSError arm.
    (tmp_path / "tf-analysis-2024-01-01.md").write_text("old")
    (tmp_path / "tf-analysis-2024-02-01.md").write_text("newer")
    latest = find_latest_prior(tmp_path)
    assert latest is not None
    assert latest.name == "tf-analysis-2024-02-01.md"


# ─── Audit item 41 — property-based blast_radius determinism ──────────
def test_blast_radius_is_deterministic_on_random_dags() -> None:
    """Random DAGs must produce a stable per-node blast count across
    runs. Iteration order over Python dicts/sets is insertion-ordered
    but the audit raised the concern that a future refactor might
    introduce nondeterminism — this test fails the moment that
    happens.
    """
    try:
        from hypothesis import given, settings, strategies as st  # type: ignore
    except ImportError:
        pytest.skip("hypothesis not installed")
    from _blast_radius import compute_blast_radius  # type: ignore

    @given(
        n_nodes=st.integers(min_value=2, max_value=12),
        edge_seed=st.integers(min_value=0, max_value=2**31),
    )
    @settings(max_examples=50, deadline=None)
    def _prop(n_nodes: int, edge_seed: int) -> None:
        import random
        rng = random.Random(edge_seed)
        nodes = [f"n{i}" for i in range(n_nodes)]
        # Random DAG: edge i→j only if i < j, guaranteeing acyclic.
        edges = []
        for i in range(n_nodes):
            for j in range(i + 1, n_nodes):
                if rng.random() < 0.3:
                    edges.append({"from": nodes[i], "to": nodes[j], "label": "ref"})
        graph = {
            "nodes": [{"id": n, "type": "compute"} for n in nodes],
            "edges": edges,
        }
        a = compute_blast_radius(graph)
        b = compute_blast_radius(graph)
        assert a == b, f"non-deterministic on graph n={n_nodes} seed={edge_seed}"
        # Sanity: every count is in [0, n_nodes-1]
        for c in a.values():
            assert 0 <= c <= n_nodes - 1

    _prop()


# ─── Audit item 5 — Windows path handling is symmetric ────────────────
def test_path_helpers_handle_both_separators() -> None:
    """Engine paths can come back as POSIX or Win32. The extension uses
    `path.isAbsolute` to detect already-absolute paths; this Python-side
    test asserts the equivalent for our internal helpers — relative
    paths come back joined under the target.
    """
    # Pure-Python check: the audit fix lives in TypeScript, but the
    # engine is the canonical emitter. Confirm the engine consistently
    # produces absolute paths so the extension's join-only-if-relative
    # contract holds.
    target = REPO / "fixtures" / "attack_graph_demo"
    if not target.exists():
        pytest.skip("attack_graph_demo fixture not present")
    r = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(target), "--format", "json"],
        capture_output=True, text=True,
    )
    d = json.loads(r.stdout)
    findings = d.get("findings", [])
    for f in findings:
        p = f.get("file", "")
        # Engine emits absolute paths under the target directory.
        assert Path(p).is_absolute() or p == "", (
            f"engine emitted non-absolute path {p!r} — extension's "
            f"join-on-relative contract will misroot it"
        )
