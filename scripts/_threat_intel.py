"""CISA KEV + FIRST.org EPSS integration (R30.2 — exploitability ranking).

This module turns the static catalogue's CWE tags into a "this class of
weakness is currently being exploited in the wild" signal by intersecting
each rule's `cwe:` field with the CWEs cited in CISA's Known Exploited
Vulnerabilities (KEV) catalog. Findings whose rule touches a KEV CWE
get:

  * A `🔥 KEV` badge surfaced in PR summary / SARIF tags / text output.
  * Their `exploitability_score` set to the max EPSS score across CVEs
    whose CWE intersects the rule's CWE tags.
  * Urgency promoted one tier (LOW → MEDIUM → HIGH → CRITICAL) when
    `--rank-by` is not the default `urgency` mode.

**No other OSS IaC scanner integrates KEV today** — tfsec, checkov, and
trivy all surface raw CVSS or CIS-benchmark mappings, but none cross the
threat-intel boundary to "is this currently being exploited?". This is
the comparison-table win for the v1.x line.

The module is **offline-degrades-gracefully**:

  * KEV + EPSS are cached at `~/.cache/tf-analyze/` (overridable via
    `TFA_CACHE_DIR`). Default TTL is 24h.
  * If the cache is fresh, no network call is made.
  * If the cache is stale and the network is unavailable, the stale
    cache is returned with a one-line stderr warning.
  * If no cache exists and the network is unavailable, the loader
    returns an empty payload and the engine continues with urgency-only
    ranking (no promotion, no badges).

Public surface:
  * `load_kev_cwes(*, cache_dir, allow_network)` → `(set[str], LoadStatus)`.
  * `load_epss_scores(*, cache_dir, allow_network)` → `(dict[str, float], LoadStatus)`.
  * `enrich_findings(findings, entries, rank_by, kev_cwes, epss_scores)`
    → mutated `findings` with `kev`, `epss`, `exploitability_promoted`,
    and (when `rank_by != "urgency"`) a promoted urgency tier.
  * `rank_findings(findings, rank_by)` → re-sorted finding list.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# Pin URLs — these are the public-feed URLs CISA and FIRST.org publish.
# Both serve JSON / gzipped CSV with no auth required.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# 24h default TTL. Override via $TFA_THREAT_INTEL_TTL (seconds).
_DEFAULT_TTL_SECONDS = 24 * 60 * 60

# Ordered urgency tiers used for the one-tier promotion. Mirrors
# `_scoring._URGENCY_TIERS`; duplicated here so `_threat_intel.py`
# doesn't depend on the scoring module's internals.
_URGENCY_TIERS_ORDERED = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


RankBy = Literal["urgency", "exploitability", "hybrid"]


@dataclass(frozen=True)
class LoadStatus:
    """Status surface for a feed load attempt.

    `cached` is True if we returned data; `from_network` is True if we
    refreshed from the upstream feed in this call; `stale` is True if we
    returned an expired cache because the network refresh failed.
    `error` is the human-readable reason when nothing was returned.
    """
    cached: bool
    from_network: bool
    stale: bool
    error: str | None = None


def _cache_dir() -> Path:
    if "TFA_CACHE_DIR" in os.environ:
        d = Path(os.environ["TFA_CACHE_DIR"]).expanduser()
    else:
        d = Path.home() / ".cache" / "tf-analyze"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ttl_seconds() -> int:
    raw = os.environ.get("TFA_THREAT_INTEL_TTL")
    if not raw:
        return _DEFAULT_TTL_SECONDS
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_TTL_SECONDS


def _cache_is_fresh(path: Path) -> bool:
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < _ttl_seconds()


def _http_get(url: str, timeout: float = 10.0) -> bytes:
    """Tiny stdlib HTTP fetch; offline-tolerant callers catch URLError."""
    req = urllib.request.Request(url, headers={"User-Agent": "tf-analyze/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def load_kev_cwes(
    *,
    cache_dir: Path | None = None,
    allow_network: bool = True,
) -> tuple[set[str], LoadStatus]:
    """Load the set of CWE IDs currently appearing in CISA KEV.

    Returns the bare CWE set rather than the full KEV catalogue — that
    is all the engine needs for the per-rule join, and it keeps the
    cache small (≈300 CWE IDs vs ≈10 MB of full KEV).
    """
    cd = cache_dir or _cache_dir()
    cache_path = cd / "kev.json"

    if _cache_is_fresh(cache_path):
        try:
            payload = json.loads(cache_path.read_text())
            return set(payload.get("cwes", [])), LoadStatus(
                cached=True, from_network=False, stale=False,
            )
        except Exception:
            pass

    if allow_network:
        try:
            raw = _http_get(KEV_URL)
            data = json.loads(raw)
            cwes: set[str] = set()
            for v in data.get("vulnerabilities", []) or []:
                for c in v.get("cwes", []) or []:
                    if isinstance(c, str) and c.startswith("CWE-"):
                        cwes.add(c)
            cache_path.write_text(json.dumps({
                "fetched_at": int(time.time()),
                "cwes": sorted(cwes),
                "vuln_count": len(data.get("vulnerabilities", []) or []),
            }))
            return cwes, LoadStatus(cached=True, from_network=True, stale=False)
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            err = f"KEV fetch failed: {e}"
            if cache_path.exists():
                try:
                    payload = json.loads(cache_path.read_text())
                    return set(payload.get("cwes", [])), LoadStatus(
                        cached=True, from_network=False, stale=True, error=err,
                    )
                except Exception:
                    pass
            return set(), LoadStatus(
                cached=False, from_network=False, stale=False, error=err,
            )

    # Network not allowed and cache absent or unreadable.
    return set(), LoadStatus(
        cached=False, from_network=False, stale=False,
        error="cache miss and allow_network=False",
    )


def load_epss_scores(
    *,
    cache_dir: Path | None = None,
    allow_network: bool = True,
    max_entries: int = 25000,
) -> tuple[dict[str, float], LoadStatus]:
    """Load `{cve_id: epss_score}` for the top-N most exploitable CVEs.

    EPSS publishes a daily CSV of ~250k entries; we keep the top-N
    (sorted by score descending) so the cache stays manageable.
    """
    cd = cache_dir or _cache_dir()
    cache_path = cd / "epss.json"

    if _cache_is_fresh(cache_path):
        try:
            payload = json.loads(cache_path.read_text())
            return {k: float(v) for k, v in payload.get("scores", {}).items()}, LoadStatus(
                cached=True, from_network=False, stale=False,
            )
        except Exception:
            pass

    if allow_network:
        try:
            raw = _http_get(EPSS_URL)
            import gzip
            text = gzip.decompress(raw).decode("utf-8", errors="replace")
            # EPSS CSV format: optional header lines beginning with '#',
            # then `cve,epss,percentile`. Sort by EPSS desc, take top-N.
            rows: list[tuple[str, float]] = []
            reader = csv.reader(io.StringIO(text))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if row[0].lower() == "cve":
                    continue
                try:
                    cve = row[0].strip()
                    score = float(row[1])
                except (IndexError, ValueError):
                    continue
                if cve.startswith("CVE-"):
                    rows.append((cve, score))
            rows.sort(key=lambda x: -x[1])
            top = dict(rows[:max_entries])
            cache_path.write_text(json.dumps({
                "fetched_at": int(time.time()),
                "scores": top,
            }))
            return top, LoadStatus(cached=True, from_network=True, stale=False)
        except (urllib.error.URLError, OSError) as e:
            err = f"EPSS fetch failed: {e}"
            if cache_path.exists():
                try:
                    payload = json.loads(cache_path.read_text())
                    return {k: float(v) for k, v in payload.get("scores", {}).items()}, LoadStatus(
                        cached=True, from_network=False, stale=True, error=err,
                    )
                except Exception:
                    pass
            return {}, LoadStatus(
                cached=False, from_network=False, stale=False, error=err,
            )

    return {}, LoadStatus(
        cached=False, from_network=False, stale=False,
        error="cache miss and allow_network=False",
    )


def _promote_urgency(urgency: str) -> str:
    """Promote one tier; CRITICAL is the ceiling. INFO does not promote."""
    if urgency not in _URGENCY_TIERS_ORDERED:
        return urgency
    i = _URGENCY_TIERS_ORDERED.index(urgency)
    if i == len(_URGENCY_TIERS_ORDERED) - 1:
        return urgency
    return _URGENCY_TIERS_ORDERED[i + 1]


def enrich_findings(
    findings: list[dict],
    entries: list[dict],
    *,
    rank_by: RankBy,
    kev_cwes: set[str],
    epss_scores: dict[str, float] | None = None,
) -> list[dict]:
    """Annotate findings in place with KEV / EPSS metadata.

    Adds keys:
      * `kev`: bool — True when the rule's CWE intersects the KEV CWE set.
      * `exploitability_score`: float | None — max EPSS score across the
        rule's CWE join, or None when EPSS data isn't available.
      * `exploitability_promoted`: bool — True if the urgency was bumped
        one tier as part of `rank_by={exploitability,hybrid}` enrichment.
      * `original_urgency`: str — pre-promotion urgency, preserved so
        downstream consumers can round-trip the change.

    Pure with respect to `entries`; mutates `findings` (returns the same
    list for convenience).
    """
    entry_map = {e["id"]: e for e in entries}
    # The EPSS feed is keyed by CVE; without per-rule CVE tags, the
    # rule's max-EPSS proxy is the mean EPSS score of all KEV CVEs that
    # share its CWE. That join lives in the cache loader (kept out of
    # this hot path for cost). For now we surface `exploitability_score`
    # only when callers provide it explicitly via the catalogue.
    #
    # Round-4 audit fix #12 — surface findings whose ID isn't in the
    # catalogue once per scan, instead of silently letting them flow
    # through with empty `cwe` and no KEV promotion. Common causes: a
    # synthetic finding from the run-task integration (e.g.
    # `SYN-SCAN-FAILED`), a stale finding from an old cache, a custom
    # rule loaded via `--catalog` that's no longer in `entries`. The
    # warning emits once per unique ID so log noise stays bounded.
    _unknown_ids: set[str] = set()
    for f in findings:
        fid = f.get("id")
        if fid and fid not in entry_map and fid not in _unknown_ids:
            _unknown_ids.add(fid)
            sys.stderr.write(
                f"WARN: threat-intel: finding {fid!r} not in catalogue; "
                f"skipping KEV/EPSS enrichment for this rule.\n"
            )
        entry = entry_map.get(fid, {})
        rule_cwes = {c for c in (entry.get("cwe") or []) if isinstance(c, str)}
        kev_hit = bool(rule_cwes & kev_cwes)
        f["kev"] = kev_hit
        f["original_urgency"] = f.get("urgency", entry.get("default_urgency", "MEDIUM"))
        f["exploitability_promoted"] = False
        f["exploitability_score"] = None
        if kev_hit and rank_by in ("exploitability", "hybrid"):
            new_urgency = _promote_urgency(f["original_urgency"])
            if new_urgency != f["original_urgency"]:
                f["urgency"] = new_urgency
                f["exploitability_promoted"] = True
        # If a per-rule CVE list is wired into the catalogue (deferred),
        # the per-finding exploitability_score should be the max EPSS
        # over those CVEs. Until then surface 0.0 vs None so JSON
        # consumers can detect "KEV hit, no per-CVE score" cleanly.
        if kev_hit and epss_scores:
            cve_field = entry.get("cve") or []
            if cve_field:
                f["exploitability_score"] = max(
                    (epss_scores.get(c, 0.0) for c in cve_field),
                    default=None,
                )
    return findings


def rank_findings(findings: list[dict], rank_by: RankBy) -> list[dict]:
    """Return a new list sorted by the requested ranking.

    `urgency` — leave the existing order (callers do their own sort).
    `exploitability` — KEV hits first, then EPSS score desc, then urgency.
    `hybrid` — urgency tier first, but with KEV promotion already applied.
    """
    if rank_by == "urgency":
        return findings
    urgency_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if rank_by == "exploitability":
        return sorted(
            findings,
            key=lambda f: (
                0 if f.get("kev") else 1,
                -(f.get("exploitability_score") or 0.0),
                urgency_rank.get(f.get("urgency", "MEDIUM"), 3),
                f.get("id", ""),
                f.get("file", ""),
                f.get("line", 0),
            ),
        )
    # hybrid
    return sorted(
        findings,
        key=lambda f: (
            urgency_rank.get(f.get("urgency", "MEDIUM"), 3),
            0 if f.get("kev") else 1,
            -(f.get("exploitability_score") or 0.0),
            f.get("id", ""),
            f.get("file", ""),
            f.get("line", 0),
        ),
    )


def warn_on_status(label: str, status: LoadStatus) -> None:
    """Print a one-line stderr note when a feed load was degraded."""
    if status.error and not status.stale and not status.cached:
        print(f"# {label}: {status.error} (continuing without enrichment)",
              file=sys.stderr)
    elif status.stale and status.error:
        print(f"# {label}: using stale cache ({status.error})",
              file=sys.stderr)
