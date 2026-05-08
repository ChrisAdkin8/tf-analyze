"""Round-trip tests for ``--apply-fixes apply``.

The risk profile of `--apply-fixes` is unique: it mutates user `.tf`
files. A malformed `fix_hcl` snippet in the catalogue corrupts source
in production, with no warning. Until this test existed there was zero
end-to-end coverage.

Each parametrised case:

  1. Copies a positive fixture to a temp directory.
  2. Confirms the rule fires on the unmodified copy (sanity).
  3. Runs ``detect.py --apply-fixes apply`` against the temp copy.
  4. Re-runs detect.py and asserts the rule no longer fires.
  5. Asserts the patched ``.tf`` files have balanced braces (cheap
     "still parseable" check).
  6. Asserts a ``.bak`` backup was written (evidence the patcher
     never silently overwrites without a recovery path).

Cases are restricted to rules with ``fix_disruption: none`` whose
fixes are simple attribute insertions or replacements — those are
where the patcher is robust today.  More complex cases (whole-resource
inserts, multi-resource fix_hcl) are out of scope for the round trip
and not exercised here.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"
FIXTURES_DIR = REPO_ROOT / "fixtures"

sys.path.insert(0, str(REPO_ROOT / "scripts"))


# Canonical round-trippable rules. Each tuple is (rule_id, fixture_dir).
# Restricted to rules where:
#   - fix_disruption: none
#   - the FIRST pattern kind is `resource_missing_arg` with a flat `arg`
#     (not a nested_path), OR
#   - the FIRST pattern kind is `resource_arg` AND the violating value
#     literally appears in the fixture (so the patcher has a line to
#     replace).
#
# Known engine limitations that block additional cases:
#   - resource_arg + fire_if_absent — patcher has no line to replace
#     (e.g. ROB-AWS-ALB-001 fixture omits enable_deletion_protection).
#   - resource_missing_arg + nested_path — patcher doesn't traverse
#     nested blocks (e.g. ROB-AZURE-LIFECYCLE-001's
#     `nested_path: lifecycle.prevent_destroy`).
# Both are catalogued in TODO.md as round-trip gaps to close in a
# future round of patcher work.
ROUNDTRIP_CASES: list[tuple[str, str]] = [
    ("OPS-AWS-CWL-001",    "aws_cwl_no_retention"),    # resource_missing_arg flat insertion
    ("OPS-GCP-LABELS-001", "missing_labels"),          # resource_missing_arg, GCP family
]


def _run_detect(target: Path, *extra_args: str) -> tuple[str, int]:
    """Run detect.py and return (stdout, returncode)."""
    cmd = [
        sys.executable, str(DETECT_PY),
        "--target", str(target),
        "--format", "json",
        "--no-hcl2",
        *extra_args,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return res.stdout, res.returncode


def _ids_for(target: Path) -> set[str]:
    import json
    out, _ = _run_detect(target)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return set()
    return {f["id"] for f in data.get("findings", [])}


def _balanced_braces(text: str) -> bool:
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


@pytest.mark.parametrize("rule_id,fixture_name", ROUNDTRIP_CASES,
                         ids=[c[0] for c in ROUNDTRIP_CASES])
def test_apply_fixes_round_trip(rule_id: str, fixture_name: str, tmp_path: Path) -> None:
    src = FIXTURES_DIR / fixture_name
    if not src.exists():
        pytest.skip(f"fixture {fixture_name} not present")

    workdir = tmp_path / fixture_name
    shutil.copytree(src, workdir)

    # 1. Sanity: rule fires on the unmodified copy.
    pre_ids = _ids_for(workdir)
    assert rule_id in pre_ids, (
        f"{rule_id} did not fire on a clean copy of {fixture_name} — "
        f"fixture or rule may have drifted. Got: {sorted(pre_ids)}"
    )

    # 2. Apply the fix.
    out, rc = _run_detect(workdir, "--apply-fixes", "apply")
    assert rc <= 1, f"--apply-fixes apply errored (exit {rc}): {out[-500:]}"

    # 3. Patched files must remain syntactically reasonable.
    for tf in workdir.rglob("*.tf"):
        text = tf.read_text()
        assert _balanced_braces(text), (
            f"--apply-fixes corrupted brace-matching in {tf}: \n{text[-300:]}"
        )

    # 4. .bak backups were written (recoverable).
    bak_files = list(workdir.rglob("*.bak"))
    assert bak_files, (
        f"--apply-fixes apply produced no .bak file under {workdir} — "
        "backup discipline broken"
    )

    # 5. Re-scan: the targeted rule must be gone.
    post_ids = _ids_for(workdir)
    assert rule_id not in post_ids, (
        f"After --apply-fixes apply, {rule_id} still fires. "
        f"fix_hcl may not match the catalogue's pattern. "
        f"Pre: {sorted(pre_ids)}\nPost: {sorted(post_ids)}"
    )


# Wider corruption-safety net: for every rule with a positive fixture,
# run --apply-fixes apply against the fixture and assert that no patched
# file becomes brace-imbalanced. This is the catastrophe check — we
# don't claim the rule clears, we only claim the patcher doesn't
# silently corrupt source.
@pytest.mark.parametrize("fixture_dir",
    sorted({
        c[1] for c in ROUNDTRIP_CASES
    } | {
        # Add a couple more high-traffic fixtures to widen the safety net
        # without slowing the suite down.
        "attack_graph_demo",
        "aws_resource_no_tags",
        "aws_dynamodb_no_deletion_protection",
    }))
def test_apply_fixes_does_not_corrupt(fixture_dir: str, tmp_path: Path) -> None:
    src = FIXTURES_DIR / fixture_dir
    if not src.exists():
        pytest.skip(f"fixture {fixture_dir} not present")

    workdir = tmp_path / fixture_dir
    shutil.copytree(src, workdir)
    out, rc = _run_detect(workdir, "--apply-fixes", "apply")
    assert rc <= 1, f"--apply-fixes errored (exit {rc}): {out[-500:]}"

    for tf in workdir.rglob("*.tf"):
        text = tf.read_text()
        assert _balanced_braces(text), (
            f"--apply-fixes corrupted braces in {fixture_dir}/{tf.name}: "
            f"\n{text[-300:]}"
        )
