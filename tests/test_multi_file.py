"""Multi-file fixtures — exercise cross-file resolution paths.

The single-rule fixtures under ``fixtures/`` are deliberately
single-file so a self-test failure points at exactly which detector
broke. But several engine features only fire in multi-file layouts:

- variable defaults declared in ``variables.tf``, referenced in ``main.tf``
- module-input flow-through (parent overrides child's var default)
- provider aliases declared in a separate file
- sensitive-variable leak through ``outputs.tf``

These fixtures live under ``fixtures/_multi_*/`` (underscore prefix
keeps them out of the parametrised single-file fixture suite). Each
test case asserts a *specific* rule fires for a *specific* reason that
can only hold when cross-file resolution works.
"""
from __future__ import annotations

from pathlib import Path

from helpers import FIXTURES_DIR, run_detect


def _ids(target: Path) -> set[str]:
    return {f["id"] for f in run_detect(target, all_rules=True)}


class TestMultiFile:
    def test_variables_split_resolves_default_from_other_file(self):
        # variables.tf declares `default = false`, main.tf references
        # `var.encrypted`. The rule fires only if the cross-file
        # extractor walks both files into the same dir-scoped dict.
        ids = _ids(FIXTURES_DIR / "_multi_variables_split")
        assert "SEC-AWS-EBS-001" in ids, (
            "Variable default in variables.tf was not folded into the "
            "resource_arg check on main.tf — cross-file var resolution "
            "broken. Got: " + str(sorted(ids))
        )

    def test_module_input_flow_through(self):
        # Parent's `module "child" { encrypted = false }` must override
        # the child module's `default = true`. Scan the project root so
        # both parent/main.tf AND modules/child/*.tf land in
        # all_files_text — that's how a user actually invokes detect.py.
        ids = _ids(FIXTURES_DIR / "_multi_module_input")
        assert "SEC-AWS-EBS-001" in ids, (
            "Module-input override (Round 24) should have flowed "
            "`encrypted = false` from the parent into the child's "
            "var.encrypted dict; SEC-AWS-EBS-001 didn't fire. "
            f"IDs: {sorted(ids)}"
        )

    def test_provider_aliases_dont_break_resource_scan(self):
        # Two `provider "aws"` blocks in providers.tf, two resources
        # in main.tf. Sanity check: detection still runs (no crash) and
        # both resources are observed (we expect at least the missing-
        # public-access-block rule to fire, since neither bucket has it).
        ids = _ids(FIXTURES_DIR / "_multi_provider_aliases")
        assert "SEC-AWS-S3-PUBLIC-BLOCK-001" in ids, (
            "Multi-provider fixture lost resource visibility — bucket-"
            "scoped rules didn't fire. IDs: " + str(sorted(ids))
        )

    def test_outputs_sensitive_leak_across_files(self):
        # variables.tf marks db_password as sensitive; outputs.tf
        # exposes it without `sensitive = true`. Rule must walk both
        # files to flag the leak.
        ids = _ids(FIXTURES_DIR / "_multi_outputs_sensitive_leak")
        assert "SEC-SENSITIVE-001" in ids or "SEC-SENSITIVE-002" in ids, (
            "Sensitive variable leak from variables.tf → outputs.tf "
            "was not detected. IDs: " + str(sorted(ids))
        )
