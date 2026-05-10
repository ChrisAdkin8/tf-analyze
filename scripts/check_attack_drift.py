#!/usr/bin/env python3
"""ATT&CK drift gate.

Verifies that the catalogue's `mitre:` references and the technique
table in `scripts/_mitre.py` are in sync. Run as a CI gate against
every push:

    python3 scripts/check_attack_drift.py

Exit codes:
  0 — catalogue and table are in sync
  1 — at least one technique cited in the catalogue isn't in the table
      (action: add an entry to MITRE_TECHNIQUE_INFO with name + tactics)

The reverse direction (entries in the table that no rule cites) is
reported as informational, not an error — having extra entries in the
table is harmless and may anticipate future catalogue work.
"""
from __future__ import annotations

import sys
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG = REPO_ROOT / "catalog"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from _mitre import MITRE_TECHNIQUE_INFO, MITRE_ATTACK_VERSION  # noqa: E402
from detect import load_yaml  # noqa: E402


def main() -> int:
    referenced: dict[str, list[str]] = defaultdict(list)
    for p in sorted(CATALOG.glob("*.yaml")):
        try:
            d = load_yaml(p.read_text())
        except Exception as e:
            print(f"WARN: cannot parse {p.name}: {e}", file=sys.stderr)
            continue
        if d.get("status") == "deprecated":
            continue
        for t in d.get("mitre") or []:
            referenced[str(t)].append(d.get("id", p.stem))

    known = set(MITRE_TECHNIQUE_INFO)
    cited = set(referenced)

    missing_from_table = sorted(cited - known)
    table_only = sorted(known - cited)

    print(f"ATT&CK pin: {MITRE_ATTACK_VERSION}")
    print(f"Catalogue cites {len(cited)} unique techniques across "
          f"{sum(len(v) for v in referenced.values())} (rule, technique) pairs.")
    print(f"Table covers {len(known)} techniques.")
    print()

    if missing_from_table:
        print("ERROR: techniques cited by the catalogue but missing from "
              "scripts/_mitre.py::MITRE_TECHNIQUE_INFO:")
        for tid in missing_from_table:
            rules = referenced[tid]
            sample = ", ".join(rules[:3]) + (f" (+{len(rules)-3} more)" if len(rules) > 3 else "")
            print(f"  {tid:14} cited by {len(rules)} rule(s): {sample}")
        print()
        print("ACTION: add each technique to MITRE_TECHNIQUE_INFO with its")
        print("  human name and tactics list. Reference: https://attack.mitre.org/techniques/")
        return 1

    if table_only:
        print(f"INFO: {len(table_only)} technique(s) in the table aren't currently "
              "cited by any rule (harmless — may anticipate future catalogue work):")
        for tid in table_only:
            name = MITRE_TECHNIQUE_INFO[tid][0]
            print(f"  {tid:14} {name}")
        print()

    print("OK: catalogue and table are in sync.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
