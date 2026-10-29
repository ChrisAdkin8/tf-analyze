"""Comment masking is cached: every rule masks the same resource bodies.

`mask_comments_and_heredocs` lost its `lru_cache` when its `heredocs` option
was added, so each body was re-walked once per rule and the corpus scan in
tests/test_perf.py got about 25% slower (it began failing CI's 5s budget on
the slower runners).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from _hcl import mask_comments, mask_comments_and_heredocs  # noqa: E402


def test_both_masks_are_cached() -> None:
    body = 'resource "x" "y" {\n  # note\n  a = "b" // c\n}\n'
    mask_comments_and_heredocs.cache_clear()
    for _ in range(3):
        mask_comments_and_heredocs(body)
        mask_comments_and_heredocs(body, heredocs=False)
    info = mask_comments_and_heredocs.cache_info()
    assert info.misses == 2 and info.hits == 4
    assert hasattr(mask_comments, "cache_info")


def test_cached_results_are_unchanged() -> None:
    body = 'a = "x" # gone\nb = <<EOT\n# kept in a heredoc\nEOT\n'
    assert "gone" not in mask_comments_and_heredocs(body)
    assert "kept" not in mask_comments_and_heredocs(body)
    assert "kept" in mask_comments_and_heredocs(body, heredocs=False)
    assert "kept" in mask_comments(body)
