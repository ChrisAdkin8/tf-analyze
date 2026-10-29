"""Rule patterns that never fired, and the gaps beside them.

* SEC-K8S-PSA-001's three `helm_set_value` patterns had `expected:` and no
  `regex:`, which the handler needs, so they were dead. The catalogue
  loader now rejects a pattern its handler can't use.
* The GCP public-access rules read the singular `member` of the
  `_iam_member` resources only; the `_iam_binding` forms (a `members`
  list) went unreported.
* IAM `NotAction` / `NotResource` was checked in `aws_iam_policy_document`
  only, not in JSON policies, and `Action: "*"` with `NotResource` (admin
  in all but name) was a HIGH wildcard action instead of the admin finding.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import _catalog
import _iam_policy
import pytest

REPO = Path(__file__).resolve().parents[1]


def _fired(target: Path, rule: str) -> set[str]:
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(target),
            "--format",
            "json",
            "--no-project-config",
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


def test_every_catalogue_pattern_has_the_keys_its_handler_needs() -> None:
    errors = []
    for yml in sorted((REPO / "catalog").glob("*.yaml")):
        data = _catalog.load_yaml(yml.read_text())
        errors += [
            e
            for e in _catalog.validate_catalog_entry(data, yml.name)
            if "never fires" in e or ".check " in e
        ]
    assert errors == []


def test_helm_set_value_without_regex_is_rejected() -> None:
    entry = {
        "id": "SEC-X-001",
        "title": "t",
        "section": "security",
        "default_urgency": "HIGH",
        "blast_radius": "module",
        "recommendation": "r",
        "verification": "v",
        "patterns": [
            {"kind": "helm_set_value", "name": "a.b", "expected": "true"},
        ],
    }
    errs = _catalog.validate_catalog_entry(entry, "x.yaml")
    assert any("needs 'regex'" in e for e in errs), errs


def test_each_psa_helm_pattern_fires_on_its_own() -> None:
    # One release per pattern in the fixture.
    assert _fired(REPO / "fixtures" / "k8s_helm_psa_disabled", "SEC-K8S-PSA-001") == {
        "helm_release.run_as_root",
        "helm_release.writable_rootfs",
        "helm_release.keeps_caps",
    }


def test_psa_helm_patterns_quiet_on_hardened_values() -> None:
    assert (
        _fired(REPO / "fixtures" / "SEC-K8S-PSA-001_clean", "SEC-K8S-PSA-001") == set()
    )


def test_gcp_public_binding_forms(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """
resource "google_project_iam_binding" "p" {
  project = "p"
  role    = "roles/viewer"
  members = ["allUsers"]
}
resource "google_cloud_run_service_iam_binding" "cr" {
  service  = "s"
  location = "l"
  role     = "roles/run.invoker"
  members  = ["user:a@example.com", "allAuthenticatedUsers"]
}
resource "google_cloud_run_v2_service_iam_binding" "cr2" {
  name     = "s"
  location = "l"
  role     = "roles/run.invoker"
  members  = ["allUsers"]
}
resource "google_cloud_run_v2_service_iam_binding" "private" {
  name     = "s"
  location = "l"
  role     = "roles/run.invoker"
  members  = ["group:callers@example.com"]
}
"""
    )
    assert _fired(tmp_path, "SEC-GCP-IAM-002") == {"google_project_iam_binding.p"}
    assert _fired(tmp_path, "SEC-GCP-CLOUDRUN-002") == {
        "google_cloud_run_service_iam_binding.cr",
        "google_cloud_run_v2_service_iam_binding.cr2",
    }


def test_bigquery_public_member_reported_once(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """
resource "google_bigquery_dataset_iam_member" "m" {
  dataset_id = "d"
  role       = "roles/bigquery.dataViewer"
  member     = "allUsers"
}
"""
    )
    assert _fired(tmp_path, "SEC-GCP-BIGQUERY-001") == {
        "google_bigquery_dataset_iam_member.m"
    }
    assert _fired(tmp_path, "SEC-GCP-IAM-002") == set()


@pytest.mark.parametrize(
    ("statement", "fires"),
    [
        # Action "*" + NotResource: the admin shape, reported once.
        (
            {"Effect": "Allow", "Action": "*", "NotResource": "arn:aws:s3:::x"},
            {"wildcard_action_and_resource"},
        ),
        (
            {
                "Effect": "Allow",
                "NotAction": ["iam:*"],
                "NotResource": ["arn:aws:s3:::x"],
            },
            {"not_action_or_not_resource"},
        ),
        (
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::x/*",
            },
            {"not_action_or_not_resource"},
        ),
        (
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
            {"not_action_or_not_resource", "wildcard_resource"},
        ),
        ({"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}, set()),
    ],
)
def test_json_negative_form_checks(statement: dict, fires: set[str]) -> None:
    (st,) = _iam_policy.json_statements({"Statement": [statement]})
    assert {c for c in sorted(_iam_policy.CHECKS) if st.matches(c)} == fires


def test_json_not_action_rule_and_admin_not_resource(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """
resource "aws_iam_policy" "json_form" {
  name = "json"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", NotAction = ["iam:*"], NotResource = ["arn:aws:s3:::a"] }]
  })
}
resource "aws_iam_role" "inline_form" {
  name               = "r"
  assume_role_policy = "{}"
  inline_policy {
    name = "p"
    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Effect = "Allow", Action = "*", NotResource = "arn:aws:s3:::a" }]
    })
  }
}
"""
    )
    assert _fired(tmp_path, "SEC-AWS-IAM-POLICY-006") == {"aws_iam_policy.json_form"}
    assert _fired(tmp_path, "SEC-AWS-IAM-JSON-003") == {"aws_iam_role.inline_form"}
    assert _fired(tmp_path, "SEC-AWS-IAM-JSON-001") == set()
