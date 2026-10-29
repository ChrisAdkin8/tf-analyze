"""A double-quoted `\\.` in a catalogue regex never matches, because the
engine's YAML reader keeps both backslashes (tasks/lessons.md, 2026-10-28).
SEC-GCP-IAM-001 shipped that way, so every dotted role alternative
(`roles/storage.admin`, ...) was missed. The loader now rejects the shape."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _catalog

REPO = Path(__file__).resolve().parents[1]


def _fired(tmp_path: Path, hcl: str, rule: str) -> set[str]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
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
    assert proc.returncode in (0, 1), proc.stderr
    return {
        f.get("resource", "")
        for f in json.loads(proc.stdout)["findings"]
        if f["id"] == rule
    }


def test_gcp_iam_dotted_admin_roles_fire(tmp_path) -> None:
    hcl = """
resource "google_project_iam_member" "storage" {
  project = "p"
  role    = "roles/storage.admin"
  member  = "user:a@example.com"
}
resource "google_project_iam_member" "security" {
  project = "p"
  role    = "roles/iam.securityAdmin"
  member  = "user:a@example.com"
}
resource "google_project_iam_binding" "compute" {
  project = "p"
  role    = "roles/compute.admin"
  members = ["user:a@example.com"]
}
resource "google_project_iam_member" "viewer" {
  project = "p"
  role    = "roles/storage.objectViewer"
  member  = "user:a@example.com"
}
"""
    assert _fired(tmp_path, hcl, "SEC-GCP-IAM-001") == {
        "google_project_iam_member.storage",
        "google_project_iam_member.security",
        "google_project_iam_binding.compute",
    }


def _backslash_errors(regex: str) -> list[str]:
    entry = {"patterns": [{"kind": "resource_arg", "regex": regex}]}
    return [e for e in _catalog.validate_catalog_entry(entry, "X") if "backslash" in e]


def test_loader_rejects_literal_backslash_before_escape() -> None:
    # What `regex: "a\\.b"` loads as.
    assert _backslash_errors("a\\\\.b")
    assert _backslash_errors("x\\\\s*=")


def test_loader_accepts_single_backslash_escapes() -> None:
    # What `regex: 'a\.b'` loads as.
    assert not _backslash_errors("a\\.b")
    assert not _backslash_errors("^roles/(owner|iam\\.securityAdmin)$")


def test_shipped_catalogue_has_no_literal_backslash_regex() -> None:
    errs = []
    for path in sorted((REPO / "catalog").glob("*.yaml")):
        data = _catalog.load_yaml(path.read_text())
        errs += [
            e
            for e in _catalog.validate_catalog_entry(data, path.name)
            if "backslash" in e
        ]
    assert errs == []
