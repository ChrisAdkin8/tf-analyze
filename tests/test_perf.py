"""Performance regression test: single-process scan of the full fixture
corpus must finish in <5s. Catches O(n^2) regressions silently slipping
into pattern matching or attack-graph construction.

Skip with TF_ANALYZE_SKIP_PERF=1 (CI runners with noisy scheduling).
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

PERF_BUDGET_SECONDS = 5.0


@pytest.mark.skipif(
    os.environ.get("TF_ANALYZE_SKIP_PERF") == "1",
    reason="Performance test skipped (TF_ANALYZE_SKIP_PERF=1)",
)
def test_corpus_scan_under_5s() -> None:
    """Walk every fixture directory in-process and scan its .tf files.

    This is intentionally NOT a subprocess test — we measure raw Python
    work, not interpreter-startup overhead. CI machines see ~2-3s; the
    5s budget gives headroom for slower laptops without making the
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

    t0 = time.perf_counter()
    total = 0
    # Per-file detection — covers the hot path the LSP and CI run.
    for fp, text in all_files.items():
        total += len(detect.detect_in_file(Path(fp), text, entries))
    # Corpus-level patterns (graph_check, cross-module).
    total += len(detect.detect_corpus(REPO_ROOT, all_files, entries))
    elapsed = time.perf_counter() - t0

    print(
        f"\n[perf] {len(all_files)} files / {len(entries)} rules "
        f"-> {total} findings in {elapsed:.3f}s",
        file=sys.stderr,
    )
    assert elapsed < PERF_BUDGET_SECONDS, (
        f"Corpus scan took {elapsed:.2f}s, exceeds {PERF_BUDGET_SECONDS}s "
        f"budget. Likely O(n^2) regression in detect_in_file or graph_check."
    )
