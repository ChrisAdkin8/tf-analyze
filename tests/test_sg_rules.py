"""Firewall rules see what `dynamic` blocks and the default security group open.

`dynamic "ingress"` over a variable used to be folded in once with its
`ingress.value.*` references unresolved, so SSH open to the world through a
variable-driven list passed. `aws_default_security_group` was not checked
at all. Each case is a small module scanned end to end.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"


@pytest.fixture(autouse=True)
def _real_parser(monkeypatch):
    # Dynamic blocks are expanded from the parse tree; the forced-fallback
    # CI job would route these modules through the legacy text path instead.
    monkeypatch.delenv("TF_ANALYZE_TEST_FORCE_FALLBACK", raising=False)


def _findings(tmp_path: Path, hcl: str, rule: str) -> list[tuple[str, str]]:
    (tmp_path / "main.tf").write_text(hcl)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return sorted(
        (f["resource"], f["urgency"])
        for f in json.loads(proc.stdout)["findings"]
        if f["id"] == rule
    )


def _sg(dynamic_for_each: str, content: str, iterator: str = "") -> str:
    it = f"\n    iterator = {iterator}" if iterator else ""
    return (
        'resource "aws_security_group" "a" {\n'
        f'  dynamic "ingress" {{\n    for_each = {dynamic_for_each}{it}\n'
        f"    content {{\n{content}\n    }}\n  }}\n}}\n"
    )


PORT_CIDRS = """      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs"""


@pytest.mark.parametrize(
    ("prelude", "for_each"),
    [
        (
            'variable "rules" {\n  default = [{ port = 22, cidrs = ["0.0.0.0/0"] }]\n}\n',
            "var.rules",
        ),
        (
            'locals {\n  rules = [{ port = 22, cidrs = ["0.0.0.0/0"] }]\n}\n',
            "local.rules",
        ),
        ("", '[{ port = 22, cidrs = ["0.0.0.0/0"] }]'),
        (
            'variable "rules" {\n  default = {\n    ssh = { port = 22, cidrs = ["0.0.0.0/0"] }\n  }\n}\n',
            "var.rules",
        ),
    ],
)
def test_dynamic_ingress_open_to_the_world_is_flagged(
    tmp_path, prelude, for_each
) -> None:
    hcl = prelude + _sg(for_each, PORT_CIDRS)
    assert _findings(tmp_path, hcl, "SEC-AWS-SG-001") == [
        ("aws_security_group.a", "CRITICAL")
    ]


def test_dynamic_ingress_with_a_named_iterator(tmp_path) -> None:
    content = PORT_CIDRS.replace("ingress.value", "rule.value")
    hcl = (
        'variable "rules" {\n  default = [{ port = 3389, cidrs = ["::/0"] }]\n}\n'
        + _sg("var.rules", content, iterator="rule")
    )
    assert _findings(tmp_path, hcl, "SEC-AWS-SG-001") == [
        ("aws_security_group.a", "CRITICAL")
    ]


def test_only_the_open_instance_counts(tmp_path) -> None:
    """Port 443 open and 22 private: open to the world, but not on SSH."""
    hcl = (
        'variable "rules" {\n  default = [\n'
        '    { port = 443, cidrs = ["0.0.0.0/0"] },\n'
        '    { port = 22, cidrs = ["10.0.0.0/8"] },\n  ]\n}\n'
        + _sg("var.rules", PORT_CIDRS)
    )
    assert _findings(tmp_path, hcl, "SEC-AWS-SG-001") == [
        ("aws_security_group.a", "HIGH")
    ]


@pytest.mark.parametrize("default", ['[{ port = 22, cidrs = ["10.0.0.0/8"] }]', "[]"])
def test_dynamic_ingress_that_is_private_or_empty_passes(tmp_path, default) -> None:
    hcl = f'variable "rules" {{\n  default = {default}\n}}\n' + _sg(
        "var.rules", PORT_CIDRS
    )
    assert _findings(tmp_path, hcl, "SEC-AWS-SG-001") == []


def test_unknown_for_each_is_not_guessed(tmp_path) -> None:
    """No default to read: nothing is known, so nothing is claimed."""
    hcl = 'variable "rules" {}\n' + _sg("var.rules", PORT_CIDRS)
    assert _findings(tmp_path, hcl, "SEC-AWS-SG-001") == []


def test_default_security_group_is_checked(tmp_path) -> None:
    open_sg = (
        'resource "aws_default_security_group" "d" {\n  vpc_id = "vpc-1"\n'
        '  ingress {\n    protocol    = "-1"\n    from_port   = 0\n    to_port     = 0\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    )
    assert _findings(tmp_path, open_sg, "SEC-AWS-SG-001") == [
        ("aws_default_security_group.d", "CRITICAL")
    ]
    self_only = (
        'resource "aws_default_security_group" "d" {\n  vpc_id = "vpc-1"\n'
        '  ingress {\n    protocol  = "-1"\n    self      = true\n    from_port = 0\n'
        "    to_port   = 0\n  }\n}\n"
    )
    assert _findings(tmp_path, self_only, "SEC-AWS-SG-001") == []


def test_azure_dynamic_security_rule(tmp_path) -> None:
    hcl = (
        'variable "rules" {\n  default = [{ name = "ssh", port = "22" }]\n}\n'
        'resource "azurerm_network_security_group" "n" {\n'
        '  name                = "n"\n  location            = "uksouth"\n'
        '  resource_group_name = "rg"\n'
        '  dynamic "security_rule" {\n    for_each = var.rules\n    content {\n'
        "      name                       = security_rule.value.name\n"
        '      priority                   = 100\n      direction                  = "Inbound"\n'
        '      access                     = "Allow"\n      protocol                   = "Tcp"\n'
        '      source_port_range          = "*"\n'
        "      destination_port_range     = security_rule.value.port\n"
        '      source_address_prefix      = "*"\n'
        '      destination_address_prefix = "*"\n    }\n  }\n}\n'
    )
    assert [r for r, _ in _findings(tmp_path, hcl, "STK-AZURE-NSG-001")] == [
        "azurerm_network_security_group.n"
    ]


def test_gcp_dynamic_allow(tmp_path) -> None:
    hcl = (
        'variable "ports" {\n  default = [["22"]]\n}\n'
        'resource "google_compute_firewall" "f" {\n  name    = "f"\n  network = "default"\n'
        '  source_ranges = ["0.0.0.0/0"]\n'
        '  dynamic "allow" {\n    for_each = var.ports\n    content {\n'
        '      protocol = "tcp"\n      ports    = allow.value\n    }\n  }\n}\n'
    )
    rules = {f for f, _ in _findings(tmp_path, hcl, "SEC-GCP-NETWORK-001")}
    assert rules == {"google_compute_firewall.f"}
