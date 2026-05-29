"""--cache correctness tests (V4).

The incremental cache keys on a corpus hash. It used to hash only `.tf`
files, but the engine also scans non-`.tf` files (workflow YAML, tfvars)
on a cache MISS — so a warm cache could silently skip a finding newly
added to one of those files while the `.tf` set was unchanged. For a
security scanner that's a control bypass ("we missed your secret"). These
tests pin that the cache invalidates on any scanned-file change.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"


def _scan(target: Path, *extra: str) -> set[str]:
    cmd = [
        sys.executable, str(DETECT_PY), "--target", str(target),
        "--format", "json", "--no-hcl2", *extra,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    try:
        return {f["id"] for f in json.loads(res.stdout).get("findings", [])}
    except json.JSONDecodeError:
        return set()


def test_cache_invalidates_on_extra_file_change(tmp_path: Path) -> None:
    # SEC-CICD-001 fires on an ungated `terraform apply` workflow YAML — an
    # `extra_text` (non-.tf) file. Start gated (suppressed) with --cache warm,
    # then remove the gate. The .tf set is unchanged, so a cache keyed only on
    # .tf would HIT and miss the now-firing rule.
    (tmp_path / "main.tf").write_text('resource "null_resource" "p" {}\n')
    wf = tmp_path / ".github" / "workflows" / "apply.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "jobs:\n  apply:\n    environment:\n      name: production\n"
        "    steps:\n      - run: terraform apply\n"
    )
    first = _scan(tmp_path, "--cache")
    assert "SEC-CICD-001" not in first  # gated; cache now warm

    wf.write_text("jobs:\n  apply:\n    steps:\n      - run: terraform apply\n")
    second = _scan(tmp_path, "--cache")
    assert "SEC-CICD-001" in second, (
        "warm --cache masked a change to a non-.tf scanned file (control bypass)"
    )


def test_cache_hit_returns_same_findings_when_unchanged(tmp_path: Path) -> None:
    # Sanity: an unchanged corpus must still produce a stable cache hit
    # (the fix must not make every run a miss).
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
    )
    first = _scan(tmp_path, "--cache")
    second = _scan(tmp_path, "--cache")
    assert first == second and first  # identical, non-empty
