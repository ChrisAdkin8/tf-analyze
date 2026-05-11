"""Scan-cache helpers for ``--cache`` mode.

Three pure functions extracted from ``detect.py`` as the
**tenth modularisation seam** (post-Session-G). All three are I/O-trivial
wrappers over a versioned JSON file at ``<workspace>/.tf-analyze-cache.json``;
the corpus hash determines whether a full re-scan is needed.

* :func:`corpus_hash` — stable 16-hex-char hash over every .tf file's
  bytes + every catalogue rule's ``id``/``patterns`` prefix. Two runs
  on byte-identical inputs produce the same hash.
* :func:`load_scan_cache` — read the cache file, return None on
  absence / version mismatch / parse error.
* :func:`save_scan_cache` — write the cache file. Failure is silent
  (caching is best-effort; a write fault must never break a scan).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def corpus_hash(all_files_text: dict, entries: list) -> str:
    """Stable 16-hex-char hash over .tf file contents + catalogue rules.

    Used by the ``--cache`` path to determine whether a full re-scan is
    needed. If every file and every catalogue entry is byte-identical
    to the previous run, the cached findings can be returned without
    re-scanning.
    """
    fh = hashlib.sha256()
    for fp_raw in sorted(all_files_text.keys(), key=str):
        fh.update(str(fp_raw).encode())
        content = all_files_text[fp_raw]
        fh.update(content.encode() if isinstance(content, str) else content)
    ch = hashlib.sha256()
    # Audit follow-up #11 — previously this hashed only the first 200
    # chars of the `patterns` field. Two catalogue entries whose
    # patterns share that prefix (common when a rule adds a new
    # alternation suffix) collided into the same cache key — a
    # catalogue update added compliance tags or pattern arms got a
    # silent cache HIT against stale findings. Hash the *whole*
    # entry's JSON repr (sorted keys, so insertion-order drift can't
    # falsify the hash) and let the hash absorb the size.
    for e in sorted(entries, key=lambda x: x["id"]):
        ch.update(e["id"].encode())
        try:
            payload = json.dumps(e, sort_keys=True, default=str)
        except TypeError:
            # Defensive: an exotic field that defies json.dumps still
            # gives a stable digest via repr (no truncation).
            payload = repr(sorted(e.items()))
        ch.update(payload.encode())
    return hashlib.sha256(
        (fh.hexdigest() + ch.hexdigest()).encode()
    ).hexdigest()[:16]


def load_scan_cache(cache_path: Path) -> dict | None:
    """Load the cache file. Returns None on absence / unreadable / wrong version.

    Version mismatch is treated as absence so the next run cleanly
    overwrites a stale schema.
    """
    try:
        with open(cache_path) as f:
            data = json.load(f)
        if data.get("version") != 1:
            return None
        return data
    except Exception:
        return None


def save_scan_cache(cache_path: Path, corpus_hash_value: str, findings: list) -> None:
    """Persist findings to the cache file. Failure is silent — non-fatal."""
    try:
        with open(cache_path, "w") as f:
            json.dump(
                {
                    "version": 1,
                    "corpus_hash": corpus_hash_value,
                    "findings": findings,
                },
                f,
            )
    except Exception:
        pass
