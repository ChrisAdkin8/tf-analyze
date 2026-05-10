"""Tests for the Session-C modularisation extract: `_catalog.py`.

The functional contracts for the catalogue loader, schema validator,
and `.tf-analyze.yaml` reader are already covered by
`tests/test_schema.py` and `tests/test_custom_rules.py`, both of
which reach them via the `detect` module's re-export shim. These
tests cover the *seam contract* — that `_catalog.py` exposes the
names callers expect, and that `detect.py` re-exports each name as a
binding (not a copy) so future renames stay in sync.

Same shape as `tests/test_session_a_extracts.py` and
`tests/test_session_b_extracts.py`.
"""
from __future__ import annotations

import sys

from helpers import REPO_ROOT


class TestCatalogModule:
    def test_module_imports_cleanly(self) -> None:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import _catalog
        # Validation domain
        assert hasattr(_catalog, "_VALID_SECTIONS")
        assert hasattr(_catalog, "_VALID_URGENCIES")
        assert hasattr(_catalog, "_VALID_BLAST_RADIUS")
        assert hasattr(_catalog, "_VALID_STATUS")
        assert hasattr(_catalog, "_VALID_FIX_DISRUPTIONS")
        assert hasattr(_catalog, "_REQUIRED_FIELDS")
        # Functions
        assert hasattr(_catalog, "load_yaml")
        assert hasattr(_catalog, "validate_catalog_entry")
        assert hasattr(_catalog, "_load_project_config")
        assert hasattr(_catalog, "load_catalog")

    def test_detect_re_exports_bindings_not_copies(self) -> None:
        """Every legacy `detect.<name>` symbol must be the same object
        as the one in `_catalog.py`. External callers reach `load_yaml`,
        `validate_catalog_entry`, and `load_catalog` through the
        `detect` namespace — if the shim ever decays into a copy, this
        catches it."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        import _catalog
        # Validation sets — `is` because the literal frozenset/set/tuple
        # identity matters (a separate `set(...)` would be a different
        # object even if the contents matched).
        assert detect._VALID_SECTIONS is _catalog._VALID_SECTIONS
        assert detect._VALID_URGENCIES is _catalog._VALID_URGENCIES
        assert detect._VALID_BLAST_RADIUS is _catalog._VALID_BLAST_RADIUS
        assert detect._VALID_STATUS is _catalog._VALID_STATUS
        assert detect._VALID_FIX_DISRUPTIONS is _catalog._VALID_FIX_DISRUPTIONS
        assert detect._REQUIRED_FIELDS is _catalog._REQUIRED_FIELDS
        # Functions
        assert detect.load_yaml is _catalog.load_yaml
        assert detect.validate_catalog_entry is _catalog.validate_catalog_entry
        assert detect._load_project_config is _catalog._load_project_config
        assert detect.load_catalog is _catalog.load_catalog

    def test_round_trip_load_real_catalog(self) -> None:
        """End-to-end smoke: detect.load_catalog must walk the live
        catalogue directory and return at least 200 active entries
        through the shim. Without this, a regression in either
        module-level import order or in `_catalog.py`'s `from _hcl
        import _parse_scalar` would only surface in a real workspace
        scan."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import detect
        entries = detect.load_catalog(REPO_ROOT / "catalog")
        # Catalogue size will move over time but should never drop
        # below 200 for an extraction-only refactor.
        assert len(entries) >= 200, f"only {len(entries)} active rules"
        # Spot-check one rule we know exists.
        ids = {e["id"] for e in entries}
        assert "SEC-AWS-S3-001" in ids or "SEC-AWS-IAM-001" in ids

    def test_validate_catalog_entry_catches_typos(self) -> None:
        """Schema validator must catch typos in domain values. Lock the
        4 most common cases at the seam — every reviewer relies on
        these to refuse bad PRs at CI time."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _catalog import validate_catalog_entry

        base = {
            "id": "TEST-001",
            "title": "Test rule",
            "section": "security",
            "default_urgency": "HIGH",
            "blast_radius": "module",
            "patterns": [{"kind": "grep", "regex": "foo"}],
            "recommendation": "fix it",
            "verification": "check it",
        }
        # Valid baseline should produce zero errors.
        assert validate_catalog_entry(base, "TEST-001.yaml") == []

        # Bad section
        bad = dict(base, section="securty")  # typo
        errs = validate_catalog_entry(bad, "TEST-001.yaml")
        assert any("section 'securty'" in e for e in errs)

        # Bad urgency
        bad = dict(base, default_urgency="CRTICAL")
        errs = validate_catalog_entry(bad, "TEST-001.yaml")
        assert any("default_urgency 'CRTICAL'" in e for e in errs)

        # Bad CWE shape (catches `732` instead of `CWE-732`)
        bad = dict(base, cwe=["732"])
        errs = validate_catalog_entry(bad, "TEST-001.yaml")
        assert any("cwe item '732'" in e for e in errs)

        # Bad D3FEND shape (catches `D3-foo` instead of `D3-FOO`)
        bad = dict(base, d3fend=["D3-foo"])
        errs = validate_catalog_entry(bad, "TEST-001.yaml")
        assert any("d3fend item 'D3-foo'" in e for e in errs)

    def test_load_yaml_round_trip(self) -> None:
        """Lock the YAML loader's catalogue-subset contract: nested
        mappings, list items with inline mappings, block scalars (`|`),
        and quote-stripping by `_parse_scalar` (which now lives in
        `_hcl.py`)."""
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from _catalog import load_yaml
        text = (
            'id: TEST-001\n'
            'title: "A test rule"\n'
            'patterns:\n'
            '  - kind: grep\n'
            '    regex: "foo.*bar"\n'
            'recommendation: |\n'
            '  Line one.\n'
            '  Line two.\n'
        )
        parsed = load_yaml(text)
        assert parsed["id"] == "TEST-001"
        # _parse_scalar (from _hcl.py) strips the surrounding quotes
        assert parsed["title"] == "A test rule"
        assert isinstance(parsed["patterns"], list)
        assert parsed["patterns"][0]["kind"] == "grep"
        assert parsed["patterns"][0]["regex"] == "foo.*bar"
        # Block scalar preserves newlines
        assert "Line one." in parsed["recommendation"]
        assert "Line two." in parsed["recommendation"]
