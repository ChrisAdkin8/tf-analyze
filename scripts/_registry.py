"""Terraform Registry staleness checks for ``MOD-STALE-001``.

Two functions extracted from ``detect.py`` as the **twelfth seam**:

* :func:`query_registry_latest` — hit the Registry's public read API
  for the latest published version of a module. ``None`` on any
  network / parse error so callers can treat absence as "unknown"
  rather than failing the scan.
* :func:`check_module_registry_staleness` — scan every ``module``
  block whose source matches ``ns/name/provider`` and emit
  ``MOD-STALE-001`` findings when the pinned version is meaningfully
  behind the registry's latest.

Staleness thresholds (intentional, calibrated to avoid noise):

* ≥ 1 major version behind → MEDIUM urgency
* ≥ 3 minor versions behind (within the same major) → LOW
* anything less → ignored

Network failures are silent — a flaky registry connection must not
emit a confusing finding. The check shares no state with the
per-file rule loop; this module imports HCL primitives + the
version-tuple helper just like detect.py does.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request

from _hcl import find_blocks, block_arg_value  # type: ignore
from _versions import _version_tuple  # type: ignore


# `find_blocks` needs the regex that opens a module block. The detect.py
# module owns this pattern but extracting the registry checker shouldn't
# require pulling in detect.py — so we accept the pattern as injected
# state at call time via the `module_start_re` argument.

_REGISTRY_SOURCE_RE = re.compile(
    r'^"?([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)"?$'
)
_MOD_VERSION_PIN_RE = re.compile(r'(?m)^\s*version\s*=\s*"([^"]+)"')


_REGISTRY_DOWN = False  # Round-5 audit fix #14 — per-process latch.


def query_registry_latest(namespace: str, name: str, provider: str) -> str | None:
    """Latest published version string from the Terraform Registry, or None.

    Returns None on any network or parse error — callers should treat
    None as "unknown" and skip the staleness check rather than erroring
    out. The 5-second timeout keeps a slow registry from stalling a
    whole scan.

    Round-5 audit fix #14 — once a single registry call has timed out,
    short-circuit subsequent calls within the same scan via the
    module-level `_REGISTRY_DOWN` latch. A 50-module workspace with
    the registry hard-down previously waited 50 × 5 = 250 seconds; now
    it waits 5 seconds total and degrades cleanly. The latch resets
    when the module is re-imported, so a follow-up scan will retry.
    """
    global _REGISTRY_DOWN
    if _REGISTRY_DOWN:
        return None
    url = f"https://registry.terraform.io/v1/modules/{namespace}/{name}/{provider}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tf-analyze/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return data.get("version") or None
    except (urllib.error.URLError, TimeoutError) as e:
        # Network-class error → trip the latch so we don't waste 5s
        # per remaining module. Other exceptions (JSONDecodeError,
        # unexpected response shape) are per-module and shouldn't
        # disable the whole check.
        _REGISTRY_DOWN = True
        sys.stderr.write(
            f"WARN: Terraform Registry unreachable ({e}); skipping "
            f"staleness checks for the remainder of this scan.\n"
        )
        return None
    except Exception:
        return None


def check_module_registry_staleness(all_files_text: dict, module_start_re) -> list[dict]:
    """Emit ``MOD-STALE-001`` findings for outdated registry modules.

    Args:
        all_files_text: Map of file path → file content (the same shape
            ``detect.py`` builds for whole-corpus passes).
        module_start_re: The compiled regex that matches the start of a
            ``module "name" { ... }`` block. Injected so this module
            doesn't have to re-define detect.py's HCL grammar.

    Returns a list of findings with the shape detect.py expects
    (``id``, ``file``, ``line``, ``resource``, ``detail``,
    ``_urgency_override``). Deduplicates per ``(namespace, name,
    provider)`` so a module referenced from many root modules only
    produces one finding.
    """
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for fp, text in all_files_text.items():
        for mblk in find_blocks(text, module_start_re):
            src = block_arg_value(mblk["body"], "source")
            if not src:
                continue
            m = _REGISTRY_SOURCE_RE.match(src.strip())
            if not m:
                continue
            ns, mod_name, provider = m.group(1), m.group(2), m.group(3)
            key = (ns, mod_name, provider)
            if key in seen:
                continue
            seen.add(key)

            pin_m = _MOD_VERSION_PIN_RE.search(mblk["body"])
            pinned = pin_m.group(1) if pin_m else None
            latest = query_registry_latest(ns, mod_name, provider)
            if not pinned or not latest:
                continue

            pinned_v = _version_tuple(pinned)
            latest_v = _version_tuple(latest)
            if not pinned_v or not latest_v or pinned_v >= latest_v:
                continue

            major_behind = latest_v[0] - pinned_v[0] if len(pinned_v) >= 1 and len(latest_v) >= 1 else 0
            minor_behind = (latest_v[1] - pinned_v[1]) if (
                len(pinned_v) >= 2 and len(latest_v) >= 2 and major_behind == 0
            ) else 0

            if major_behind >= 1:
                urgency = "MEDIUM"
            elif minor_behind >= 3:
                urgency = "LOW"
            else:
                continue  # minor drift < 3 — not worth flagging

            findings.append({
                "id": "MOD-STALE-001",
                "file": str(fp),
                "line": mblk["start_line"],
                "resource": f"module.{mblk['groups'][0]}",
                "detail": (
                    f"{ns}/{mod_name}/{provider}: pinned={pinned}, "
                    f"latest={latest} ({major_behind}M/{minor_behind}m behind)"
                ),
                "_urgency_override": urgency,
            })

    return findings
