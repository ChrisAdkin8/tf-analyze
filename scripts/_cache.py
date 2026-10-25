"""Scan-cache helpers for ``--cache`` mode.

Three pure functions extracted from ``detect.py`` as the
**tenth modularisation seam** (post-Session-G). All three are I/O-trivial
wrappers over a versioned JSON file at ``<workspace>/.tf-analyze-cache.json``;
the corpus hash determines whether a full re-scan is needed.

* :func:`corpus_hash` — stable 16-hex-char hash over every .tf file's
  bytes + every catalogue rule + the engine's own source and vendored
  parser versions. Two runs of the same engine on byte-identical inputs
  produce the same hash.
* :func:`load_scan_cache` — read the cache file, return None on
  absence / version mismatch / parse error.
* :func:`save_scan_cache` — write the cache file. Failure is silent
  (caching is best-effort; a write fault must never break a scan).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Bump when the cache file layout or the hash inputs change, so caches
# written by an older engine are treated as absent. v2: the hash also
# covers the engine source and parser versions (parser migration,
# tasks/hcl-parser-migration.md §4.9).
CACHE_FORMAT_VERSION = 2


def _engine_fingerprint() -> str:
    """Hash of the loaded engine modules' source plus the vendored parser
    versions. A handler or parser change alters detection results without
    touching the corpus or the catalogue, so without this a warm cache
    would keep returning the old engine's findings.

    Only modules that live next to this file are hashed (``detect`` and
    its ``_*.py`` siblings, in both the source and installed layouts).
    """
    from _hcl import HCL2_VERSION, LARK_VERSION

    here = Path(__file__).resolve().parent
    h = hashlib.sha256(f"hcl2={HCL2_VERSION};lark={LARK_VERSION}".encode())
    for name, mod in sorted(sys.modules.items()):
        f = getattr(mod, "__file__", None)
        if not f or Path(f).resolve().parent != here:
            continue
        try:
            h.update(name.encode())
            h.update(Path(f).read_bytes())
        except OSError:
            continue
    return h.hexdigest()


def corpus_hash(all_files_text: dict, entries: list) -> str:
    """Stable 16-hex-char hash over .tf file contents + catalogue rules.

    Used by the ``--cache`` path to determine whether a full re-scan is
    needed. If every file and every catalogue entry is byte-identical
    to the previous run, and the engine and parser are unchanged, the
    cached findings can be returned without re-scanning.
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
        (fh.hexdigest() + ch.hexdigest() + _engine_fingerprint()).encode()
    ).hexdigest()[:16]


def load_scan_cache(cache_path: Path) -> dict | None:
    """Load the cache file. Returns None on absence / unreadable / wrong version.

    Version mismatch is treated as absence so the next run cleanly
    overwrites a stale schema.
    """
    try:
        with open(cache_path) as f:
            data = json.load(f)
        if data.get("version") != CACHE_FORMAT_VERSION:
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
                    "version": CACHE_FORMAT_VERSION,
                    "corpus_hash": corpus_hash_value,
                    "findings": findings,
                },
                f,
            )
    except Exception:
        pass
