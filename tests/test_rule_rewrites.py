"""Parser migration Step 4 (tasks/hcl-parser-migration.md §4.10, §10).

Pins: `firewall_open_port` models inbound exposure for AWS, Azure and GCP
(egress / deny / outbound rules and non-world sources never match, on the
tree and the regex fallback alike); SEC-AWS-SG-001 and STK-AZURE-NSG-001
use it instead of file-wide text search; structured `escalation: match:`
raises urgency (ports, attribute regexes) and is validated at load; and
every remaining `grep` pattern records why it stays a text scan.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _catalog  # noqa: E402
import detect  # noqa: E402

CATALOG = detect.load_catalog(REPO_ROOT / "catalog", include_stubs=True)
ENTRIES = {e["id"]: e for e in CATALOG}


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


@pytest.fixture(params=["tree", "fallback"])
def path_mode(request, monkeypatch):
    if request.param == "fallback":
        monkeypatch.setenv("TF_ANALYZE_TEST_FORCE_FALLBACK", "1")
    return request.param


def _scan(text: str, rule: str, tmp_path: Path, var_defaults: dict | None = None) -> list[dict]:
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    return detect.detect_in_file(fp, text, [ENTRIES[rule]], var_defaults)


def _urgency(findings: list[dict], rule: str) -> str | None:
    if not findings:
        return None
    return findings[0].get("urgency") or ENTRIES[rule]["default_urgency"]


# ---- SEC-AWS-SG-001 ----------------------------------------------------------

def _sg(ingress: str = "", egress: str = "") -> str:
    return f'resource "aws_security_group" "sg" {{\n  name = "sg"\n{ingress}{egress}}}\n'


def _block(kind: str, port: int, cidr: str = '["0.0.0.0/0"]', protocol: str = "tcp",
           key: str = "cidr_blocks") -> str:
    return (f"  {kind} {{\n    from_port = {port}\n    to_port = {port}\n"
            f'    protocol = "{protocol}"\n    {key} = {cidr}\n  }}\n')


def test_sg_open_ingress_fires_high(tmp_path, path_mode) -> None:
    f = _scan(_sg(_block("ingress", 443)), "SEC-AWS-SG-001", tmp_path)
    assert len(f) == 1 and _urgency(f, "SEC-AWS-SG-001") == "HIGH"
    assert f[0]["resource"] == "aws_security_group.sg" and f[0]["line"] == 1
    assert "_open_port_ranges" not in f[0]


def test_sg_open_ssh_escalates_to_critical(tmp_path, path_mode) -> None:
    f = _scan(_sg(_block("ingress", 22)), "SEC-AWS-SG-001", tmp_path)
    assert _urgency(f, "SEC-AWS-SG-001") == "CRITICAL"


def test_sg_all_protocols_covers_ssh(tmp_path, path_mode) -> None:
    f = _scan(_sg(_block("ingress", 0, protocol="-1")), "SEC-AWS-SG-001", tmp_path)
    assert _urgency(f, "SEC-AWS-SG-001") == "CRITICAL"


def test_sg_port_range_covers_rdp(tmp_path, path_mode) -> None:
    text = _sg("  ingress {\n    from_port = 3000\n    to_port = 4000\n    protocol = \"tcp\"\n"
               "    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n")
    assert _urgency(_scan(text, "SEC-AWS-SG-001", tmp_path), "SEC-AWS-SG-001") == "CRITICAL"


def test_sg_egress_and_private_ingress_are_clean(tmp_path, path_mode) -> None:
    text = _sg(_block("ingress", 22, cidr='["10.0.0.0/8"]'), _block("egress", 0, protocol="-1"))
    assert _scan(text, "SEC-AWS-SG-001", tmp_path) == []


def test_sg_ipv6_world(tmp_path, path_mode) -> None:
    text = _sg(_block("ingress", 443, cidr='["::/0"]', key="ipv6_cidr_blocks"))
    assert _scan(text, "SEC-AWS-SG-001", tmp_path)


def test_sg_cidr_from_variable_default(tmp_path, path_mode) -> None:
    text = 'variable "open" {\n  default = ["0.0.0.0/0"]\n}\n' + _sg(_block("ingress", 22, cidr="var.open"))
    vd = detect._extract_var_defaults_by_dir({str(tmp_path / "main.tf"): text})[str(tmp_path)]
    f = _scan(text, "SEC-AWS-SG-001", tmp_path, vd)
    assert _urgency(f, "SEC-AWS-SG-001") == "CRITICAL"


def test_sg_cidr_from_local(tmp_path, path_mode) -> None:
    text = 'locals {\n  world = "0.0.0.0/0"\n}\n' + _sg(_block("ingress", 443, cidr="[local.world]"))
    vd = detect._extract_var_defaults_by_dir({str(tmp_path / "main.tf"): text})[str(tmp_path)]
    assert _scan(text, "SEC-AWS-SG-001", tmp_path, vd)


def test_sg_unresolvable_cidr_does_not_fire(tmp_path, path_mode) -> None:
    assert _scan(_sg(_block("ingress", 22, cidr="var.unknown")), "SEC-AWS-SG-001", tmp_path) == []


def test_sg_ingress_attribute_form_on_tree_path(tmp_path) -> None:
    text = ('resource "aws_security_group" "sg" {\n  ingress = [{\n    from_port = 22\n'
            '    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }]\n}\n')
    assert _urgency(_scan(text, "SEC-AWS-SG-001", tmp_path), "SEC-AWS-SG-001") == "CRITICAL"


def test_sg_heredoc_text_is_not_a_rule(tmp_path, path_mode) -> None:
    text = ('resource "aws_security_group" "sg" {\n  description = <<EOT\n'
            'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}\nEOT\n}\n')
    assert _scan(text, "SEC-AWS-SG-001", tmp_path) == []


def test_sg_rule_resource_ingress_only(tmp_path, path_mode) -> None:
    def rule(t: str) -> str:
        return (f'resource "aws_security_group_rule" "r" {{\n  type = "{t}"\n  from_port = 22\n'
                f'  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n'
                f'  security_group_id = "sg-1"\n}}\n')
    assert _urgency(_scan(rule("ingress"), "SEC-AWS-SG-001", tmp_path), "SEC-AWS-SG-001") == "CRITICAL"
    assert _scan(rule("egress"), "SEC-AWS-SG-001", tmp_path) == []


def test_vpc_ingress_rule_resource(tmp_path, path_mode) -> None:
    text = ('resource "aws_vpc_security_group_ingress_rule" "r" {\n  security_group_id = "sg-1"\n'
            '  cidr_ipv4 = "0.0.0.0/0"\n  ip_protocol = "-1"\n}\n')
    assert _urgency(_scan(text, "SEC-AWS-SG-001", tmp_path), "SEC-AWS-SG-001") == "CRITICAL"


def test_count_zero_skips_only_a_literal(tmp_path, path_mode) -> None:
    """`count = 0` literally means the resource isn't created; a count from
    a variable default can be overridden by tfvars, so it still reports."""
    sg = _sg(_block("ingress", 443))
    literal = sg.replace('  name = "sg"\n', '  name = "sg"\n  count = 0\n')
    assert _scan(literal, "SEC-AWS-SG-001", tmp_path) == []
    text = 'variable "n" {\n  default = 0\n}\n' + sg.replace('  name = "sg"\n', '  name = "sg"\n  count = var.n\n')
    vd = detect._extract_var_defaults_by_dir({str(tmp_path / "main.tf"): text})[str(tmp_path)]
    assert _scan(text, "SEC-AWS-SG-001", tmp_path, vd)


def test_unresolvable_rule_type_fails_closed(tmp_path, path_mode) -> None:
    text = ('resource "aws_security_group_rule" "r" {\n  type = var.rule_type\n  from_port = 22\n'
            '  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n'
            '  security_group_id = "sg-1"\n}\n')
    assert _urgency(_scan(text, "SEC-AWS-SG-001", tmp_path), "SEC-AWS-SG-001") == "CRITICAL"


def test_dynamic_ingress_counts(tmp_path, path_mode) -> None:
    text = ('resource "aws_security_group" "sg" {\n  dynamic "ingress" {\n    for_each = [22]\n'
            '    content {\n      from_port = 22\n      to_port = 22\n      protocol = "tcp"\n'
            '      cidr_blocks = ["0.0.0.0/0"]\n    }\n  }\n}\n')
    assert _urgency(_scan(text, "SEC-AWS-SG-001", tmp_path), "SEC-AWS-SG-001") == "CRITICAL"


# ---- STK-AZURE-NSG-001 --------------------------------------------------------

def _nsg_rule(direction="Inbound", access="Allow", source='"*"', port='"22"') -> str:
    return (f'resource "azurerm_network_security_rule" "r" {{\n  direction = "{direction}"\n'
            f'  access = "{access}"\n  protocol = "Tcp"\n  source_address_prefix = {source}\n'
            f'  destination_port_range = {port}\n}}\n')


def test_nsg_inbound_allow_internet(tmp_path, path_mode) -> None:
    assert _urgency(_scan(_nsg_rule(), "STK-AZURE-NSG-001", tmp_path), "STK-AZURE-NSG-001") == "CRITICAL"
    f = _scan(_nsg_rule(source='"Internet"', port='"443"'), "STK-AZURE-NSG-001", tmp_path)
    assert _urgency(f, "STK-AZURE-NSG-001") == "HIGH"


@pytest.mark.parametrize("kw", [{"direction": "Outbound"}, {"access": "Deny"},
                                {"source": '"10.0.0.0/8"'}, {"source": '"VirtualNetwork"'}])
def test_nsg_non_exposing_rules_are_clean(kw, tmp_path, path_mode) -> None:
    assert _scan(_nsg_rule(**kw), "STK-AZURE-NSG-001", tmp_path) == []


def test_nsg_unresolvable_direction_and_access_fail_closed(tmp_path, path_mode) -> None:
    f = _scan(_nsg_rule(direction="${var.direction}", access="${var.access}"),
              "STK-AZURE-NSG-001", tmp_path)
    assert _urgency(f, "STK-AZURE-NSG-001") == "CRITICAL"


def test_nsg_inline_security_rule(tmp_path, path_mode) -> None:
    text = ('resource "azurerm_network_security_group" "g" {\n  security_rule {\n'
            '    direction = "Inbound"\n    access = "Allow"\n    protocol = "Tcp"\n'
            '    source_address_prefix = "*"\n    destination_port_range = "3000-4000"\n  }\n}\n')
    assert _urgency(_scan(text, "STK-AZURE-NSG-001", tmp_path), "STK-AZURE-NSG-001") == "CRITICAL"


# ---- GCP firewall_open_port (existing rules, generalised handler) ------------

def _fw(source='["0.0.0.0/0"]', ports='["22"]', direction=None) -> str:
    d = f'  direction = "{direction}"\n' if direction else ""
    p = f"    ports = {ports}\n" if ports is not None else ""
    return (f'resource "google_compute_firewall" "f" {{\n  name = "f"\n{d}'
            f'  allow {{\n    protocol = "tcp"\n{p}  }}\n  source_ranges = {source}\n}}\n')


def test_gcp_ssh_open(tmp_path, path_mode) -> None:
    assert _scan(_fw(), "SEC-GCP-NETWORK-001", tmp_path)
    assert _scan(_fw(ports='["20-25"]'), "SEC-GCP-NETWORK-001", tmp_path)


def test_gcp_allow_without_ports_means_all_ports(tmp_path, path_mode) -> None:
    assert _scan(_fw(ports=None), "SEC-GCP-NETWORK-001", tmp_path)


def test_gcp_iap_range_and_comments_are_clean(tmp_path, path_mode) -> None:
    text = _fw(source='["35.235.240.0/20"]').replace(
        "  allow {", "  # IAP range - no need to open 0.0.0.0/0\n  allow {")
    assert _scan(text, "SEC-GCP-NETWORK-001", tmp_path) == []


def test_gcp_egress_is_clean(tmp_path, path_mode) -> None:
    assert _scan(_fw(direction="EGRESS"), "SEC-GCP-NETWORK-001", tmp_path) == []


# ---- structured escalation on attributes --------------------------------------

def test_gcp_iam_escalates_on_all_users(tmp_path, path_mode) -> None:
    member = ('resource "google_project_iam_member" "m" {\n  project = "p"\n'
              '  role = "roles/owner"\n  member = "%s"\n}\n')
    assert _urgency(_scan(member % "allUsers", "SEC-GCP-IAM-001", tmp_path), "SEC-GCP-IAM-001") == "CRITICAL"
    assert _urgency(_scan(member % "user:a@b.c", "SEC-GCP-IAM-001", tmp_path), "SEC-GCP-IAM-001") == "HIGH"
    binding = ('resource "google_project_iam_binding" "b" {\n  project = "p"\n'
               '  role = "roles/editor"\n  members = ["user:a@b.c", "allAuthenticatedUsers"]\n}\n')
    assert _urgency(_scan(binding, "SEC-GCP-IAM-001", tmp_path), "SEC-GCP-IAM-001") == "CRITICAL"


def test_escalation_never_lowers_and_ignores_free_text(tmp_path) -> None:
    entry = {"id": "T", "default_urgency": "HIGH", "escalation": [
        {"condition": "lower it", "match": {"name": "x"}, "urgency": "LOW"},
        {"condition": "is_production_environment", "urgency": "CRITICAL"}],
        "patterns": [{"kind": "resource_missing_arg", "resource": "aws_thing", "arg": "tags"}]}
    text = 'resource "aws_thing" "a" {\n  name = "x"\n}\n'
    fp = tmp_path / "main.tf"
    fp.write_text(text)
    found = detect.detect_in_file(fp, text, [entry])
    assert found and found[0].get("urgency", "HIGH") == "HIGH"


# ---- catalogue validation -------------------------------------------------------

BASE = {"id": "X-001", "title": "t", "section": "security", "default_urgency": "HIGH",
        "blast_radius": "module", "status": "active", "patterns": [{"kind": "grep", "regex": "x"}],
        "recommendation": "r", "verification": "v"}


@pytest.mark.parametrize("esc, ok", [
    ([{"condition": "free text", "new_urgency": "CRITICAL"}], True),
    ([{"condition": "c", "match": {"ports": ["22"]}, "urgency": "CRITICAL"}], True),
    ([{"condition": "c", "match": {"member": "^allUsers$"}, "urgency": "CRITICAL"}], True),
    ([{"urgency": "CRITICAL"}], False),                                  # neither form
    ([{"condition": "c", "urgency": "URGENT"}], False),                  # bad urgency
    ([{"condition": "c", "match": {"ports": ["ssh"]}, "urgency": "CRITICAL"}], False),
    ([{"condition": "c", "match": {"member": "("}, "urgency": "CRITICAL"}], False),
])
def test_escalation_validation(esc, ok) -> None:
    errs = [e for e in _catalog.validate_catalog_entry({**BASE, "escalation": esc}, "x.yaml")
            if "escalation" in e]
    assert (not errs) == ok, errs


def test_shipped_structured_escalations_load_as_mappings() -> None:
    """The stdlib YAML loader misreads a nested mapping that is the first
    key of a list item; pin that the shipped ones load correctly."""
    for rid in ("SEC-AWS-SG-001", "STK-AZURE-NSG-001", "SEC-GCP-IAM-001"):
        matches = [x.get("match") for x in ENTRIES[rid]["escalation"] if "match" in x]
        assert matches and all(isinstance(m, dict) and m for m in matches), (rid, matches)


# ---- remaining text scans are deliberate -----------------------------------------

def test_every_grep_pattern_says_why_it_is_a_text_scan() -> None:
    missing = [e["id"] for e in CATALOG for p in e.get("patterns") or []
               if p.get("kind") == "grep" and not str(p.get("text_scan", "")).strip()]
    assert not missing, f"grep patterns without a text_scan reason: {missing}"


def test_network_rules_no_longer_use_grep() -> None:
    for rid in ("SEC-AWS-SG-001", "STK-AZURE-NSG-001"):
        assert {p["kind"] for p in ENTRIES[rid]["patterns"]} == {"firewall_open_port"}


# ---- structural text scans use the HCL-aware lexer (`code_only`) -----------

def _prov(prefix: str) -> str:
    return (f'resource "null_resource" "x" {{\n{prefix}'
            '  provisioner "local-exec" {\n    command = "echo hi"\n  }\n}\n')


@pytest.mark.parametrize("prefix", [
    # A heredoc with an odd number of quotes: a quote-toggling stripper
    # loses track of string state after it.
    '  triggers = {\n    note = <<EOT\nshe said "hi\nEOT\n  }\n',
    # A string ending in an escaped backslash (`\\` then the closing quote).
    '  triggers = {\n    path = "C:\\\\"\n  }\n',
    # `#` inside a string is not a comment.
    '  triggers = {\n    tag = "a#b"\n  }\n',
])
def test_provisioner_after_tricky_text_is_still_found(prefix, tmp_path) -> None:
    assert _scan(_prov(prefix), "SEC-PROVISIONER-001", tmp_path)


def test_commented_and_heredoc_provisioner_text_is_ignored(tmp_path) -> None:
    commented = 'resource "null_resource" "x" {\n  # provisioner "local-exec" {\n  #   command = "x"\n  # }\n}\n'
    in_heredoc = ('resource "null_resource" "x" {\n  triggers = {\n    doc = <<EOT\n'
                  'provisioner "local-exec" {\nEOT\n  }\n}\n')
    assert _scan(commented, "SEC-PROVISIONER-001", tmp_path) == []
    assert _scan(in_heredoc, "SEC-PROVISIONER-001", tmp_path) == []


def test_structural_text_scans_use_code_only() -> None:
    """Rules about Terraform structure use the HCL-aware lexer; the rules
    that must see heredoc text (secrets, container definitions) keep the
    comment-only `hcl_context`."""
    for e in CATALOG:
        for p in e.get("patterns") or []:
            if p.get("kind") != "grep":
                continue
            reason = str(p.get("text_scan", ""))
            if reason.startswith("Terraform structure"):
                assert p.get("code_only") and not p.get("hcl_context"), e["id"]
