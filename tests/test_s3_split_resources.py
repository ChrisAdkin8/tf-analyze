"""AWS provider v4+ split S3 configuration into sibling resources
(`aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`,
…). Rules written for the legacy inline blocks must accept the split form
(`unless_companion`), and name-scoped rules must honour `name_regex`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _handlers_generic as hg
import detect

REPO = Path(__file__).resolve().parents[1]
S3_IDS = {"SEC-AWS-S3-001", "ROB-AWS-S3-001", "SEC-AWS-LOG-RETENTION-001"}

BUCKET = 'resource "aws_s3_bucket" "%s" {\n  bucket = "%s"\n}\n'
VERSIONING = """resource "aws_s3_bucket_versioning" "v_%s" {
  bucket = %s
  versioning_configuration {
    status = "Enabled"
  }
}
"""
ENCRYPTION = """resource "aws_s3_bucket_server_side_encryption_configuration" "e_%s" {
  bucket = %s
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
"""


def _findings(tmp_path: Path, files: dict[str, str]) -> set[tuple]:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        (f["id"], f["resource"])
        for f in json.loads(out.stdout)["findings"]
        if f["id"] in S3_IDS
    }


def test_companions_in_another_file_satisfy_legacy_patterns(tmp_path) -> None:
    assert (
        _findings(
            tmp_path,
            {
                "main.tf": BUCKET % ("data", "my-data"),
                "s3.tf": VERSIONING % ("data", "aws_s3_bucket.data.id")
                + ENCRYPTION % ("data", "aws_s3_bucket.data.bucket"),
            },
        )
        == set()
    )


def test_companion_by_literal_bucket_name(tmp_path) -> None:
    found = _findings(
        tmp_path,
        {
            "main.tf": BUCKET % ("data", "my-data")
            + VERSIONING % ("data", '"my-data"'),
        },
    )
    assert ("ROB-AWS-S3-001", "aws_s3_bucket.data") not in found
    assert ("SEC-AWS-S3-001", "aws_s3_bucket.data") in found  # no encryption


def test_companion_for_another_bucket_does_not_count(tmp_path) -> None:
    found = _findings(
        tmp_path,
        {
            "main.tf": BUCKET % ("data", "my-data")
            + BUCKET % ("data2", "other")
            + VERSIONING % ("x", "aws_s3_bucket.data2.id"),
        },
    )
    assert ("ROB-AWS-S3-001", "aws_s3_bucket.data") in found
    assert ("ROB-AWS-S3-001", "aws_s3_bucket.data2") not in found
    # `data` is not a prefix match for `data2` (and vice versa).
    assert ("SEC-AWS-S3-001", "aws_s3_bucket.data") in found


def test_bucket_without_any_versioning_or_encryption_still_fires(tmp_path) -> None:
    assert _findings(tmp_path, {"main.tf": BUCKET % ("data", "my-data")}) == {
        ("SEC-AWS-S3-001", "aws_s3_bucket.data"),
        ("ROB-AWS-S3-001", "aws_s3_bucket.data"),
    }


def test_log_retention_rule_only_fires_on_log_buckets(tmp_path) -> None:
    found = _findings(
        tmp_path,
        {
            "main.tf": BUCKET % ("app", "my-app-assets")
            + BUCKET % ("trail", "org-cloudtrail-logs")
            + BUCKET % ("x", "audit-archive"),
        },
    )
    log_rule = {r for i, r in found if i == "SEC-AWS-LOG-RETENTION-001"}
    assert log_rule == {"aws_s3_bucket.trail", "aws_s3_bucket.x"}


def test_has_companion_reference_forms() -> None:
    blk = detect.find_blocks(BUCKET % ("b", "n"), detect.RESOURCE_START)[0]
    spec = {"resource": "aws_s3_bucket_versioning", "via": "bucket"}
    for ref in (
        "aws_s3_bucket.b.id",
        "aws_s3_bucket.b[0].id",
        '"${aws_s3_bucket.b.bucket}"',
        '"n"',
    ):
        cands = detect.find_blocks(VERSIONING % ("v", ref), detect.RESOURCE_START)
        assert hg._has_companion(blk, spec, cands), ref
    for ref in ("aws_s3_bucket.bb.id", "module.x.aws_s3_bucket.b.id", '"m"'):
        cands = detect.find_blocks(VERSIONING % ("v", ref), detect.RESOURCE_START)
        assert not hg._has_companion(blk, spec, cands), ref


# ---- plan / state mode agree with static -----------------------------------------

def _catalog_entries(*ids: str) -> list[dict]:
    from _catalog import load_yaml

    return [load_yaml((REPO / "catalog" / f"{i}.yaml").read_text()) for i in ids]


def _plan(tmp_path: Path, with_reference: bool) -> Path:
    bucket = {"address": "aws_s3_bucket.data", "mode": "managed",
              "type": "aws_s3_bucket", "name": "data",
              "values": {"bucket": "my-data"}}
    # Before apply the companion's `bucket` (= aws_s3_bucket.data.id) is
    # unknown, so planned_values omit it; only the configuration links them.
    versioning = {"address": "aws_s3_bucket_versioning.v", "mode": "managed",
                  "type": "aws_s3_bucket_versioning", "name": "v",
                  "values": {"versioning_configuration": [{"status": "Enabled"}]}}
    config = {"address": "aws_s3_bucket_versioning.v", "expressions": {
        "bucket": {"references": ["aws_s3_bucket.data.id", "aws_s3_bucket.data"]
                   if with_reference else ["aws_s3_bucket.other.id"]}}}
    plan = {"planned_values": {"root_module": {"resources": [bucket, versioning]}},
            "configuration": {"root_module": {"resources": [config]}}}
    path = tmp_path / f"plan-{with_reference}.json"
    path.write_text(json.dumps(plan))
    return path


def test_plan_mode_companion_via_configuration_reference(tmp_path) -> None:
    import _plan_state

    [entry] = _catalog_entries("ROB-AWS-S3-001")

    def hit(path: Path) -> list[dict]:
        return [f for f in _plan_state.detect_in_plan(path, [entry])
                if f["resource"] == "aws_s3_bucket.data"]

    assert not hit(_plan(tmp_path, with_reference=True))
    assert hit(_plan(tmp_path, with_reference=False))


def test_state_mode_companion_and_name_regex(tmp_path) -> None:
    import _plan_state

    entries = _catalog_entries("ROB-AWS-S3-001", "SEC-AWS-LOG-RETENTION-001")
    resources = [
        {"address": "aws_s3_bucket.app", "type": "aws_s3_bucket", "name": "app",
         "values": {"bucket": "my-app-assets"}},
        {"address": "aws_s3_bucket_versioning.v", "type": "aws_s3_bucket_versioning",
         "name": "v", "values": {"bucket": "my-app-assets"}},
    ]
    found = _plan_state.evaluate_against_resources(
        resources, entries, finding_mode="state", file_marker="<state>")
    # Versioned by value (state knows it), and not a log bucket by name.
    assert not [f for f in found if f["resource"] == "aws_s3_bucket.app"]
