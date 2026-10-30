"""Performance regression test: single-process scan of the full fixture
corpus must finish in <8s. Catches O(n^2) regressions silently slipping
into pattern matching or attack-graph construction.

Skip with TF_ANALYZE_SKIP_PERF=1 (CI runners with noisy scheduling).

The scan is timed up to PERF_ATTEMPTS times and passes on the first run
under budget. A shared CI runner sometimes stalls one run; an O(n^2)
regression is slow every time.

The budget was 5s. Rules that read the parse tree instead of grepping
(#98-#101) made the scan ~11% slower (1.34s -> 1.49s on a laptop), and
the py3.10 CI job, ~3.7x slower than a laptop, then took 5.4-5.6s on
every run. 8s leaves ~45% headroom there; a quadratic blow-up is many
times slower, not 45%.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import detect  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "fixtures"
CATALOG_DIR = REPO_ROOT / "catalog"

PERF_BUDGET_SECONDS = 8.0
PERF_ATTEMPTS = 3


@pytest.mark.skipif(
    os.environ.get("TF_ANALYZE_SKIP_PERF") == "1",
    reason="Performance test skipped (TF_ANALYZE_SKIP_PERF=1)",
)
def test_corpus_scan_within_budget() -> None:
    """Walk every fixture directory in-process and scan its .tf files.

    This is intentionally NOT a subprocess test — we measure raw Python
    work, not interpreter-startup overhead. CI machines see ~4-5.5s; the
    8s budget gives headroom for slower runners without making the
    threshold meaningless.
    """
    entries = detect.load_catalog(CATALOG_DIR)
    fixture_dirs = sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())

    # Pre-load all .tf files so I/O isn't conflated with detection time.
    all_files: dict[str, str] = {}
    for d in fixture_dirs:
        for tf in d.glob("*.tf"):
            try:
                all_files[str(tf)] = tf.read_text()
            except OSError:
                continue
    assert all_files, "Expected non-empty fixture corpus"

    timings: list[float] = []
    for _ in range(PERF_ATTEMPTS):
        t0 = time.perf_counter()
        total = 0
        # Per-file detection — covers the hot path the LSP and CI run.
        for fp, text in all_files.items():
            total += len(detect.detect_in_file(Path(fp), text, entries))
        # Corpus-level patterns (graph_check, cross-module).
        total += len(detect.detect_corpus(REPO_ROOT, all_files, entries))
        elapsed = time.perf_counter() - t0
        timings.append(elapsed)

        print(
            f"\n[perf] {len(all_files)} files / {len(entries)} rules "
            f"-> {total} findings in {elapsed:.3f}s",
            file=sys.stderr,
        )
        if elapsed < PERF_BUDGET_SECONDS:
            return

    runs = ", ".join(f"{t:.2f}s" for t in timings)
    pytest.fail(
        f"Corpus scan took {runs} ({PERF_ATTEMPTS} runs), all over the "
        f"{PERF_BUDGET_SECONDS}s budget. Likely O(n^2) regression in "
        f"detect_in_file or graph_check."
    )


LEADING_OPERATOR = "locals {\n  x = (var.a\n    || var.b)\n}\n"


@pytest.mark.skipif(
    os.environ.get("TF_ANALYZE_SKIP_PERF") == "1",
    reason="Performance test skipped (TF_ANALYZE_SKIP_PERF=1)",
)
def test_rejected_file_with_many_policies(tmp_path, monkeypatch) -> None:
    """A rejected file parses each policy on its own: linear in the number
    of policies, once per policy rather than once per rule. Padding each
    block's fragment to its line in the file made this quadratic, and
    1,100 documents ran six rules out of time (30s, finding lost)."""
    monkeypatch.setattr(detect, "RULE_TIMEOUTS", [])
    pairs = "".join(
        f'data "aws_iam_policy_document" "d{i}" {{\n  statement {{\n'
        f'    actions   = ["s3:Get{i}"]\n    resources = ["x"]\n  }}\n}}\n'
        f'resource "aws_iam_policy" "p{i}" {{\n  policy = <<P\n'
        f'{{"Statement":[{{"Effect":"Allow","Action":"s3:Get{i}","Resource":"x"}}]}}\nP\n}}\n'
        for i in range(1100)
    )
    admin = (
        'data "aws_iam_policy_document" "admin" {\n  statement {\n'
        '    actions   = ["*"]\n    resources = ["*"]\n  }\n}\n'
    )
    text = LEADING_OPERATOR + pairs + admin
    entries = [
        e for e in detect.load_catalog(CATALOG_DIR)
        if any(str(p.get("kind", "")).startswith("iam_") for p in e.get("patterns") or [])
    ]
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    start = time.perf_counter()
    found = detect.detect_in_file(fp, text, entries)
    elapsed = time.perf_counter() - start
    assert "SEC-AWS-IAM-POLICY-005" in {f["id"] for f in found}
    assert not detect.RULE_TIMEOUTS
    assert elapsed < 20.0, f"{elapsed:.1f}s"


def test_deep_parentheses_are_linear() -> None:
    """Stripping one layer per pass over the text was quadratic: 30,000
    layers took 30s."""
    import _hcl

    text = "(" * 30000 + '"x"' + ")" * 30000
    start = time.perf_counter()
    assert _hcl._strip_parens(text) == '"x"'
    assert time.perf_counter() - start < 2.0


def test_block_header_does_not_backtrack() -> None:
    """Each comment between labels has one way to match: a lazy `.*?` let
    runs of comments split many ways (1.1s at 24, doubling each time)."""
    text = "resource " + "/* c */ " * 200 + "x\n"
    start = time.perf_counter()
    assert detect.RESOURCE_START.search(text) is None
    assert detect.DATA_START.search(text.replace("resource", "data")) is None
    assert time.perf_counter() - start < 1.0
