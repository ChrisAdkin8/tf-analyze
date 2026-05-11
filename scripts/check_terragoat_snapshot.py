#!/usr/bin/env python3
"""Compare current `examples/terragoat/{aws,gcp,azure}` finding counts to
the checked-in snapshot at `tests/snapshots/terragoat.json`. CI fails if
any cloud drifts more than the snapshot's `tolerance_pct`.

Audit item 38 — the previous CI step embedded hand-coded bounds in
`.github/workflows/ci.yml`. Those bounds got stale every ~10 rules and
needed a manual two-line yaml edit per drift; this script reads the
snapshot file as the source of truth so updates land alongside a rule
change in the same PR.

Usage:
    python3 scripts/check_terragoat_snapshot.py            # CI: assert match
    python3 scripts/check_terragoat_snapshot.py --update   # rewrite snapshot
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SNAPSHOT = REPO / "tests" / "snapshots" / "terragoat.json"
DETECT = REPO / "scripts" / "detect.py"
CLOUDS = ("gcp", "aws", "azure")


def _count(target: Path) -> int:
    r = subprocess.run(
        ["python3", str(DETECT), "--target", str(target), "--format", "json"],
        capture_output=True,
        text=True,
    )
    # detect.py exits 1 when findings are present — both 0 and 1 are
    # success here. Anything else is a real engine crash.
    if r.returncode > 1:
        sys.stderr.write(r.stderr)
        raise SystemExit(f"detect.py crashed on {target} (exit {r.returncode})")
    return len(json.loads(r.stdout)["findings"])


def _measure() -> dict[str, int]:
    out: dict[str, int] = {}
    for c in CLOUDS:
        out[c] = _count(REPO / "examples" / "terragoat" / c)
    out["total"] = _count(REPO / "examples" / "terragoat")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update", action="store_true", help="overwrite the snapshot")
    args = ap.parse_args()

    current = _measure()
    snap = json.loads(SNAPSHOT.read_text())
    expected = snap["counts"]
    tol_pct = float(snap.get("_meta", {}).get("tolerance_pct", 15))

    if args.update:
        snap["counts"] = current
        SNAPSHOT.write_text(json.dumps(snap, indent=2) + "\n")
        print(f"[snapshot] updated → {current}")
        return 0

    drift_lines = []
    for k, want in expected.items():
        got = current.get(k, 0)
        if want == 0:
            ok = got == 0
        else:
            ok = abs(got - want) / want * 100 <= tol_pct
        marker = "ok" if ok else "DRIFT"
        drift_lines.append(f"  {k}: want={want} got={got} [{marker}]")
        if not ok:
            drift_lines.append(
                f"    drift={abs(got - want)} ({abs(got - want) / want * 100:.1f}%)"
                f", tolerance={tol_pct}%"
            )

    drifted = any("DRIFT" in line for line in drift_lines)
    print("\n".join(drift_lines))
    if drifted:
        print(
            "\nSnapshot drift exceeds tolerance. If deliberate (new rule pack),"
            " run `python3 scripts/check_terragoat_snapshot.py --update` and"
            " commit `tests/snapshots/terragoat.json`.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
