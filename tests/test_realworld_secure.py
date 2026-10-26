"""Secure, idiomatic Terraform must not draw HIGH or CRITICAL findings.

Every rule's positive fixture shows it can fire; nothing showed it stays
quiet on real secure code written the way people write it (fmt-aligned,
for_each, current provider argument names, Deny statements, native S3
locking ...). Each directory under tests/realworld_secure/ is one such
idiom. MEDIUM and below are out of scope: hygiene rules fire on most
real code by design.

KNOWN_FALSE_POSITIVES is a ratchet, exact in both directions: a new HIGH
or CRITICAL fails the test, and so does a listed one that stops firing,
until it is removed from the list. The directory is in the repo's
`.tf-analyze.yaml` ignore_paths so these do not count against its badge.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "tests" / "realworld_secure"
CASES = sorted(p.name for p in CORPUS.iterdir() if p.is_dir())

KNOWN_FALSE_POSITIVES: dict[str, dict[str, str]] = {
    "azure_linux_vm_ssh_only": {
        "SEC-AZURE-VM-001": "disable_password_authentication defaults to true",
    },
    "azure_mssql_entra_only": {
        "SEC-AZURE-SQL-001": "wants a resource that does not exist; ignores azuread_administrator",
        "STK-AZURE-SQL-TDE-001": "wants a resource that does not exist; TDE is on by default",
    },
    "git_module_sha_pin": {
        "MOD-PIN-001": "a 40-char SHA ?ref= is a pin",
        "SEC-SUPPLY-001": "looks for a module argument `ref`; the ref lives in the source URL",
    },
    "kubernetes_secret_from_sensitive_var": {
        "SEC-K8S-SECRET-001": "fires on any data, even from a sensitive variable",
    },
    "pinned_registry_module": {
        "MOD-SUPPLY-003": "grep on the source line ignores the version argument",
    },
}


def _high_or_critical(case: str) -> set[str]:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(CORPUS / case),
            "--format",
            "json",
            "--show-info",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    findings = json.loads(proc.stdout)["findings"]
    return {f["id"] for f in findings if f.get("urgency") in ("HIGH", "CRITICAL")}


def test_known_list_names_real_cases() -> None:
    assert set(KNOWN_FALSE_POSITIVES) <= set(CASES)


@pytest.mark.parametrize("case", CASES)
def test_secure_idiom_has_no_unexpected_high_findings(case: str) -> None:
    fired = _high_or_critical(case)
    known = set(KNOWN_FALSE_POSITIVES.get(case, {}))
    new = fired - known
    fixed = known - fired
    assert not new, f"{case}: new HIGH/CRITICAL false positive(s): {sorted(new)}"
    assert not fixed, (
        f"{case}: {sorted(fixed)} no longer fire — remove them from "
        f"KNOWN_FALSE_POSITIVES"
    )
