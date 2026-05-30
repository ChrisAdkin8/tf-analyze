"""Policy-as-code DSL handler — the `kind: policy` corpus detector.

Thin seam: the expression evaluator + resource model live in `_policy.py`
(pure, unit-testable). This module just registers the corpus handler that runs
a policy pattern over the workspace resource index.
"""
from __future__ import annotations

from detect import CorpusCtx, _register_corpus
from _policy import evaluate_policy


@_register_corpus("policy")
def _corpus_policy(c: CorpusCtx) -> list[dict]:
    """`kind: policy` — evaluate the pattern's `match` + `require`/`forbid`
    expressions over every resource; emit a finding per violation."""
    return evaluate_policy(c.pat, c.eid, c.resource_index_cache)
