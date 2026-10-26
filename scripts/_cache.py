"""Scan-cache helpers for ``--cache`` mode.

Three pure functions extracted from ``detect.py`` as the
**tenth modularisation seam** (post-Session-G). All three are I/O-trivial
wrappers over a versioned JSON file (default: per-target, under the user
cache dir — see `default_cache_path`);
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
import os
import sys
import tempfile
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


def default_cache_path(target: Path) -> Path:
    """Where `--cache` keeps a target's findings unless `--cache-file` is
    given: the user cache dir, keyed by the target's resolved path.

    Never inside the target. The cache is trusted whenever its corpus
    hash matches, and anyone can compute that hash from public inputs, so
    a cache file committed to the scanned repo (say, by a pull request)
    could replay ``"findings": []`` and score the repo clean; a symlink
    committed in its place would redirect the cache write.
    """
    from _hcl import _user_cache_dir

    key = hashlib.sha256(str(target.resolve()).encode()).hexdigest()[:16]
    return _user_cache_dir() / "tf-analyze" / "scan-cache" / f"{key}.json"


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


def save_scan_cache(
    cache_path: Path,
    corpus_hash_value: str,
    findings: list,
    *,
    parse_fallback_files: list | None = None,
) -> None:
    """Persist findings (and the files scanned in parse-fallback mode, so a
    cache hit still reports them) to the cache file. Failure is silent —
    non-fatal.

    Written to a temporary file and renamed into place, so a symlink at
    `cache_path` is replaced rather than followed (no write through it to
    another file) and a crash never leaves a half-written cache.
    """
    tmp_name = None
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", dir=cache_path.parent, prefix=".tf-analyze-cache-",
            suffix=".tmp", delete=False,
        ) as f:
            tmp_name = f.name
            json.dump(
                {
                    "version": CACHE_FORMAT_VERSION,
                    "corpus_hash": corpus_hash_value,
                    "findings": findings,
                    "parse_fallback_files": parse_fallback_files or [],
                },
                f,
            )
        os.replace(tmp_name, cache_path)
        tmp_name = None
    except Exception:
        pass
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
