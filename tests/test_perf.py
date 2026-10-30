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

import json
import os
import subprocess
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


# ---- Suggestions -------------------------------------------------------------
# Trying the patcher per finding once cost findings x file size in every scan:
# 480 KB with 3,000 findings went from 4.6s to 357s. Scan time here is mostly
# detection, so the budgets are generous; the old cost is many times over them.
SUGGESTION_TABLES = 2000  # about 300 KB, about 2,000 fixable findings
SCAN_BUDGET_SECONDS = 15.0
SUGGESTED_SCAN_BUDGET_SECONDS = 20.0


def _timed_scan(target: Path, *flags: str) -> tuple[float, dict]:
    best, report = float("inf"), {}
    for _ in range(PERF_ATTEMPTS):
        t0 = time.perf_counter()
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"), "--target", str(target),
             "--no-threat-intel", "--format", "json", *flags],
            capture_output=True, text=True, check=False,
        )
        best = min(best, time.perf_counter() - t0)
        report = json.loads(res.stdout)
        if best < SCAN_BUDGET_SECONDS:
            break
    return best, report


@pytest.fixture
def large_file(tmp_path: Path) -> Path:
    (tmp_path / "main.tf").write_text("\n".join(
        f'resource "aws_dynamodb_table" "t{i}" {{\n  name = "t{i}"\n  hash_key = "id"\n'
        f'  billing_mode = "PAY_PER_REQUEST"\n  attribute {{\n    name = "id"\n'
        f'    type = "S"\n  }}\n}}\n'
        for i in range(SUGGESTION_TABLES)
    ))
    return tmp_path


@pytest.mark.skipif(
    os.environ.get("TF_ANALYZE_SKIP_PERF") == "1",
    reason="Performance test skipped (TF_ANALYZE_SKIP_PERF=1)",
)
def test_a_plain_scan_does_not_pay_for_suggestions(large_file: Path) -> None:
    elapsed, report = _timed_scan(large_file)
    assert not [f for f in report["findings"] if "fix_suggestion" in f]
    assert elapsed < SCAN_BUDGET_SECONDS


@pytest.mark.skipif(
    os.environ.get("TF_ANALYZE_SKIP_PERF") == "1",
    reason="Performance test skipped (TF_ANALYZE_SKIP_PERF=1)",
)
def test_suggestions_stay_close_to_linear(large_file: Path) -> None:
    """The Action's JSON run; `--mode pr-review` takes the same path."""
    elapsed, report = _timed_scan(large_file, "--fix-suggestions")
    assert len([f for f in report["findings"] if "fix_suggestion" in f]) >= SUGGESTION_TABLES
    assert elapsed < SUGGESTED_SCAN_BUDGET_SECONDS
