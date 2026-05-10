"""MITRE ATT&CK reference data + helpers for the tf-analyze engine.

Extracted from `detect.py` as the first low-risk seam in the broader
modularisation. Pure data + helpers — no engine state, no I/O. Safe
to import from anywhere; no circular-dependency risk.

What lives here:
  * `MITRE_ATTACK_VERSION` — the ATT&CK release the catalogue is pinned
    against. Bump when the catalogue is re-mapped against a newer
    release; the drift-check script (`scripts/check_attack_drift.py`)
    verifies referenced techniques still exist at the pinned version.
  * `MITRE_TECHNIQUE_INFO` — `{technique_id: (human_name, [tactics])}`.
    New techniques get added here when the catalogue starts citing them.
    Sourced from attack.mitre.org/techniques/<id>/.
  * `MITRE_TACTIC_ORDER` — display order for ATT&CK Enterprise tactics
    (the kill-chain shape SOC analysts read by). Drives `--format mitre`
    output grouping.

What stays in `detect.py`:
  * Render functions (`_render_mitre`) and their integration with the
    rest of the dispatch / output pipeline.
  * SARIF emission (consumes the constants here).

Why this seam:
  * `detect.py` is 8000+ lines monolithic. Extracting *data* + pure
    functions before extracting *behaviour* is the lowest-risk way to
    start modularising — there's no dispatch logic to break, no
    coupling with the rest of the engine, and the test surface is
    trivial (look up a known technique → get a known name).
  * The MITRE constants are also referenced by the drift-check script
    (which would otherwise have to import all of `detect.py` just to
    read this dict).
"""
from __future__ import annotations


# ATT&CK release the catalogue's `mitre:` technique IDs are pinned
# against. Bump this when re-mapping the catalogue against a newer
# ATT&CK release; CI / `scripts/check_attack_drift.py` verifies
# referenced techniques still exist at the pinned version.
MITRE_ATTACK_VERSION = "v17"  # April 2025 release; current as of catalogue sweep 2026-05-10


# `{technique_id: (human name, [tactics in display order])}`.
# Covers every technique referenced by the catalogue. Add a new entry
# here when the catalogue starts citing a previously-unknown technique
# — the drift-check script will flag it on next CI run if you forget.
MITRE_TECHNIQUE_INFO: dict[str, tuple[str, list[str]]] = {
    "T1040":      ("Network Sniffing",                                              ["Credential Access", "Discovery"]),
    "T1059":      ("Command and Scripting Interpreter",                             ["Execution"]),
    "T1068":      ("Exploitation for Privilege Escalation",                         ["Privilege Escalation"]),
    "T1071.001":  ("Application Layer Protocol: Web Protocols",                     ["Command and Control"]),
    "T1078":      ("Valid Accounts",                                                ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1078.004":  ("Valid Accounts: Cloud Accounts",                                ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1098.001":  ("Account Manipulation: Additional Cloud Credentials",            ["Persistence", "Privilege Escalation"]),
    "T1110.001":  ("Brute Force: Password Guessing",                                ["Credential Access"]),
    "T1133":      ("External Remote Services",                                      ["Initial Access", "Persistence"]),
    "T1190":      ("Exploit Public-Facing Application",                             ["Initial Access"]),
    "T1195.002":  ("Compromise Software Supply Chain",                              ["Initial Access"]),
    "T1485":      ("Data Destruction",                                              ["Impact"]),
    "T1490":      ("Inhibit System Recovery",                                       ["Impact"]),
    "T1496":      ("Resource Hijacking",                                            ["Impact"]),
    "T1530":      ("Data from Cloud Storage",                                       ["Collection"]),
    "T1542.003":  ("Pre-OS Boot: Bootkit",                                          ["Defense Evasion", "Persistence"]),
    "T1552.001":  ("Unsecured Credentials: Credentials In Files",                   ["Credential Access"]),
    "T1552.004":  ("Unsecured Credentials: Private Keys",                           ["Credential Access"]),
    "T1552.005":  ("Unsecured Credentials: Cloud Instance Metadata API",            ["Credential Access"]),
    "T1556.006":  ("Modify Authentication Process: Multi-Factor Authentication",    ["Credential Access", "Defense Evasion", "Persistence"]),
    "T1562.001":  ("Impair Defenses: Disable or Modify Tools",                      ["Defense Evasion"]),
    "T1562.004":  ("Impair Defenses: Disable or Modify System Firewall",            ["Defense Evasion"]),
    "T1562.008":  ("Impair Defenses: Disable or Modify Cloud Logs",                 ["Defense Evasion"]),
    "T1583.002":  ("Acquire Infrastructure: DNS Server",                            ["Resource Development"]),
    "T1611":      ("Escape to Host",                                                ["Privilege Escalation"]),
    # ---- R30.3 / R30.4 / R30.5 additions (2026-05-11) ----
    "T1059.004":  ("Command and Scripting Interpreter: Unix Shell",                 ["Execution"]),
    "T1070.001":  ("Indicator Removal: Clear Windows Event Logs",                   ["Defense Evasion"]),
    "T1105":      ("Ingress Tool Transfer",                                         ["Command and Control"]),
    "T1195.001":  ("Supply Chain Compromise: Compromise Software Dependencies and Development Tools", ["Initial Access"]),
    "T1199":      ("Trusted Relationship",                                          ["Initial Access"]),
    "T1499.002":  ("Endpoint Denial of Service: Service Exhaustion Flood",          ["Impact"]),
    "T1525":      ("Implant Internal Image",                                        ["Persistence"]),
    "T1565":      ("Data Manipulation",                                             ["Impact"]),
    "T1565.001":  ("Data Manipulation: Stored Data Manipulation",                   ["Impact"]),
    "T1574.002":  ("Hijack Execution Flow: DLL Side-Loading",                       ["Persistence", "Privilege Escalation", "Defense Evasion"]),
}


# Display order for ATT&CK Enterprise tactics — the kill-chain shape
# SOC analysts read by. Drives `--format mitre` output's H2 grouping.
MITRE_TACTIC_ORDER: list[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def mitre_technique_name(tid: str) -> str:
    """Look up a technique's human name; return the empty string for
    unknown techniques so callers can fall back to the bare ID without
    breaking the output rendering."""
    info = MITRE_TECHNIQUE_INFO.get(tid)
    return info[0] if info else ""


def mitre_technique_tactics(tid: str) -> list[str]:
    """Return the tactics a technique belongs to. An unknown technique
    is grouped under the synthetic 'Other' tactic so it's still
    surfaced rather than silently dropped from `--format mitre`."""
    info = MITRE_TECHNIQUE_INFO.get(tid)
    return info[1] if info else ["Other"]
