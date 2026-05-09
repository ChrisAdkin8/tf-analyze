"""Smoke tests for the Terraform provider build + binary shape.

The provider is a Go module under `terraform-provider/`; its own test
file (`scan_data_source_test.go`) covers the Go internals. These
Python-side tests confirm that:

  * The Go module compiles on this machine (catches dependency drift,
    missing imports, typos in struct tags). Auto-skipped if `go` isn't
    on PATH so CI environments without Go can still run the suite.
  * The compiled binary responds to `-help` (sanity check the
    plugin-protocol entry point boots).
  * The repo-shape contract holds: provider directory, go.mod,
    main.go, internal/provider/*.go, examples, README — all present
    so distribution-checklist items don't silently regress.

A full Terraform acceptance test (running `terraform plan` against the
plugin and asserting state shape) is the natural follow-up and would
pull in `terraform-plugin-testing` plus a Terraform binary on PATH.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
PROVIDER_DIR = REPO_ROOT / "terraform-provider"


# ---------------------------------------------------------------------------
# Repo-shape contract — files we promise are there.
# ---------------------------------------------------------------------------


class TestProviderRepoShape:
    def test_provider_directory_exists(self) -> None:
        assert PROVIDER_DIR.is_dir(), "terraform-provider/ directory missing"

    def test_go_mod_present(self) -> None:
        gomod = PROVIDER_DIR / "go.mod"
        assert gomod.exists()
        text = gomod.read_text()
        assert "module github.com/ChrisAdkin8/terraform-provider-tfanalyze" in text
        # terraform-plugin-framework must be the declared dep (or the
        # module won't expose any provider surface).
        assert "terraform-plugin-framework" in text

    def test_main_entry_point_present(self) -> None:
        main_go = PROVIDER_DIR / "main.go"
        assert main_go.exists()
        text = main_go.read_text()
        # Plugin address — this is what `source = "ChrisAdkin8/tfanalyze"`
        # in user HCL resolves to.
        assert "registry.terraform.io/ChrisAdkin8/tfanalyze" in text

    def test_provider_implementation_present(self) -> None:
        for name in ("provider.go", "scan_data_source.go"):
            p = PROVIDER_DIR / "internal" / "provider" / name
            assert p.exists(), f"missing {p}"

    def test_data_source_example_present(self) -> None:
        ex = (PROVIDER_DIR / "examples" / "data-sources" / "tfanalyze_scan"
              / "data-source.tf")
        assert ex.exists(), "examples/data-sources/tfanalyze_scan/data-source.tf missing"
        text = ex.read_text()
        # The headline example must show: data source declaration +
        # gating idiom (precondition / count). These are user-facing
        # promises from the README.
        assert 'data "tfanalyze_scan"' in text
        assert "precondition" in text or "count" in text

    def test_readme_present(self) -> None:
        readme = PROVIDER_DIR / "README.md"
        assert readme.exists()
        text = readme.read_text()
        assert "tfanalyze_scan" in text
        assert "score" in text and "grade" in text


# ---------------------------------------------------------------------------
# Go build — catches dependency drift, struct-tag typos, etc.
# ---------------------------------------------------------------------------


class TestProviderGoBuild:
    def test_go_compiles_the_provider(self, tmp_path: Path) -> None:
        if shutil.which("go") is None:
            pytest.skip("go toolchain not on PATH")
        out_bin = tmp_path / "terraform-provider-tfanalyze"
        result = subprocess.run(
            ["go", "build", "-o", str(out_bin), "."],
            cwd=str(PROVIDER_DIR),
            capture_output=True, text=True, timeout=180,
        )
        assert result.returncode == 0, (
            f"go build failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert out_bin.exists()
        assert out_bin.stat().st_size > 0

    def test_go_unit_tests_pass(self) -> None:
        if shutil.which("go") is None:
            pytest.skip("go toolchain not on PATH")
        result = subprocess.run(
            ["go", "test", "./..."],
            cwd=str(PROVIDER_DIR),
            capture_output=True, text=True, timeout=180,
        )
        assert result.returncode == 0, (
            f"go test failed:\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_built_binary_responds_to_help(self, tmp_path: Path) -> None:
        # The plugin-protocol binary supports `-help` (per
        # `flag.Parse()` in main.go); a real plugin invocation
        # requires Terraform proxying, which we don't replicate here.
        if shutil.which("go") is None:
            pytest.skip("go toolchain not on PATH")
        out_bin = tmp_path / "terraform-provider-tfanalyze"
        subprocess.run(
            ["go", "build", "-o", str(out_bin), "."],
            cwd=str(PROVIDER_DIR), check=True, timeout=180,
        )
        result = subprocess.run(
            [str(out_bin), "-help"],
            capture_output=True, text=True, timeout=10,
        )
        # `-help` exits non-zero by Go's flag-parsing convention but
        # prints the usage to stderr.
        combined = result.stdout + result.stderr
        assert "-debug" in combined, (
            f"`-help` should advertise -debug (the plugin-debug flag). "
            f"Got:\n{combined}"
        )
