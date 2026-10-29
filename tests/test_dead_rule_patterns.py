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
    errs = _catalog.validate_catalog_entry(entry, "SEC-X-001.yaml")
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
# ---- review fixes: per-pattern drop, literal-only helm values, table gaps

_CUSTOM_RULE = """\
id: CUSTOM-HELM-001
title: "helm release hardening"
section: security
default_urgency: MEDIUM
blast_radius: module
patterns:
  - kind: helm_set_value
    resource: helm_release
    name: service.type
    regex: '^LoadBalancer$'
  - kind: helm_set_value
    resource: helm_release
    name: securityContext.runAsNonRoot
    expected: 'true'
recommendation: TODO
verification: TODO
"""

_LB_RELEASE = """
resource "helm_release" "lb" {
  name  = "lb"
  chart = "app"
  set {
    name  = "service.type"
    value = "LoadBalancer"
  }
}
"""


def _scan_custom(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess:
    rules = tmp_path / ".tf-analyze-rules"
    rules.mkdir(exist_ok=True)
    (rules / "CUSTOM-HELM-001.yaml").write_text(_CUSTOM_RULE)
    (tmp_path / ".tf-analyze.yaml").write_text("rules_dir: .tf-analyze-rules\n")
    (tmp_path / "main.tf").write_text(_LB_RELEASE)
    return subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "detect.py"),
            "--target",
            str(tmp_path),
            "--format",
            "json",
            "--fail-on",
            "MEDIUM",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_dead_pattern_in_custom_rule_keeps_the_working_one(tmp_path: Path) -> None:
    # The whole rule used to be dropped, so the gate passed (exit 0).
    proc = _scan_custom(tmp_path)
    assert proc.returncode == 1, proc.stderr
    ids = {(f["id"], f["resource"]) for f in json.loads(proc.stdout)["findings"]}
    assert ("CUSTOM-HELM-001", "helm_release.lb") in ids
    assert "WARN: CUSTOM-HELM-001: skipping patterns[1]" in proc.stderr


def test_dead_pattern_in_custom_rule_is_fatal_under_strict(tmp_path: Path) -> None:
    proc = _scan_custom(tmp_path, "--strict-catalog")
    assert proc.returncode == 2, proc.stderr
    assert "needs 'regex'" in proc.stderr


def test_rule_with_no_usable_pattern_is_skipped_loudly(tmp_path: Path, capsys) -> None:
    catalog = tmp_path / "catalog"
    catalog.mkdir()
    (catalog / "SEC-DEAD-001.yaml").write_text(
        _CUSTOM_RULE.replace("CUSTOM-HELM-001", "SEC-DEAD-001").replace(
            "    regex: '^LoadBalancer$'\n", ""
        )
    )
    assert _catalog.load_catalog(catalog) == []
    err = capsys.readouterr().err
    assert "SEC-DEAD-001: no usable patterns left" in err


def _entry(pattern: dict) -> dict:
    return {
        "id": "SEC-X-001",
        "title": "t",
        "section": "security",
        "default_urgency": "HIGH",
        "blast_radius": "module",
        "recommendation": "r",
        "verification": "v",
        "patterns": [pattern],
    }


@pytest.mark.parametrize(
    ("pattern", "needle"),
    [
        ({"kind": "hcl_attr", "resource": "x", "path": "a.b"}, "needs 'not_equal'"),
        ({"kind": "resource_absent"}, "needs 'resource'"),
        (
            {"kind": "graph_check", "function": "no_such_check"},
            ".function 'no_such_check' not in",
        ),
        ({"kind": "iam_json_policy_analysis", "check": "nope"}, ".check 'nope' not in"),
    ],
)
def test_unusable_patterns_are_reported(pattern: dict, needle: str) -> None:
    errs = _catalog.validate_catalog_entry(_entry(pattern), "SEC-X-001.yaml")
    assert any(needle in e for e in errs), errs
    unusable: dict = {}
    assert (
        _catalog.validate_catalog_entry(_entry(pattern), "SEC-X-001.yaml", unusable=unusable)
        == []
    )
    assert 0 in unusable


_HELM_EXPRESSIONS = """
variable "m" {
  type    = map(string)
  default = { drop = "{ALL}" }
}
resource "helm_release" "a_lookup" {
  name  = "a"
  chart = "app"
  set {
    name  = "securityContext.capabilities.drop"
    value = lookup(var.m, "drop")
  }
}
resource "helm_release" "b_tostring" {
  name  = "b"
  chart = "app"
  set {
    name  = "securityContext.capabilities.drop"
    value = tostring(var.m["drop"])
  }
}
resource "helm_release" "c_empty" {
  name  = "c"
  chart = "app"
  set {
    name  = "securityContext.capabilities.drop"
    value = ""
  }
}
resource "helm_release" "d_interp" {
  name  = "d"
  chart = "app"
  set {
    name  = "securityContext.capabilities.drop"
    value = "{${var.m["drop"]}}"
  }
}
resource "helm_release" "e_v3_literal" {
  name  = "e"
  chart = "app"
  set = [
    { name = "securityContext.runAsNonRoot", value = "false" },
    { name = "securityContext.capabilities.drop", value = "{NET_RAW}" },
  ]
}
"""


@pytest.mark.parametrize("fallback", ["0", "1"])
def test_psa_helm_judges_literal_values_only(
    tmp_path: Path, monkeypatch, fallback: str
) -> None:
    # Expressions are unknown here, on the parse-tree and the regex
    # fallback path alike; only the literal v3 item fires.
    monkeypatch.setenv("TF_ANALYZE_TEST_FORCE_FALLBACK", fallback)
    (tmp_path / "main.tf").write_text(_HELM_EXPRESSIONS)
    assert _fired(tmp_path, "SEC-K8S-PSA-001") == {"helm_release.e_v3_literal"}
