"""Entropy-based secret detection (`kind: high_entropy_string`).

Unit tests for the entropy math, the charset/length/exclusion classifier, and
the in-file handler. End-to-end coverage (rule fires on the dirty fixture, stays
silent on the clean one) is provided by `scripts/self_test.py` via the fixtures
declared in `catalog/SEC-SECRETS-ENTROPY-001.yaml`.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import _handlers_security as H  # noqa: E402
from _hcl import find_blocks  # noqa: E402
from detect import RESOURCE_START  # noqa: E402

# A well-known *example* AWS secret-key string (not a live credential).
TOKEN = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"


def _ctx(tf: str, pat: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        pat=pat or {},
        eid="SEC-SECRETS-ENTROPY-001",
        file_path=Path("main.tf"),
        resources=find_blocks(tf, RESOURCE_START),
    )


class TestShannonEntropy:
    def test_empty_is_zero(self):
        assert H._shannon_entropy("") == 0.0

    def test_uniform_is_zero(self):
        assert H._shannon_entropy("aaaaaa") == 0.0

    def test_two_symbols_is_one_bit(self):
        assert abs(H._shannon_entropy("abab") - 1.0) < 1e-9

    def test_random_token_clears_threshold(self):
        assert H._shannon_entropy(TOKEN) >= 4.0


class TestClassifier:
    @pytest.mark.parametrize("v", [
        TOKEN,                                        # AWS secret-style, H=4.61
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",   # GitHub PAT-ish, H=4.14
        "kT9xQ2mZ7pL4vR8nW1cF3hJ6dS5gB0yA7zXqWeRt",   # random base64 token
    ])
    def test_real_tokens_detected(self, v):
        assert H._is_high_entropy_secret(v, min_len=20, max_len=100, min_entropy=4.0)

    @pytest.mark.parametrize("v", [
        "us-east-1",                                   # too short
        "postgres",                                    # too short, low entropy
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",    # git SHA — hex, H≈3.74 < 4.0
        "9f86d081884c7d659a2feaa0c55ad015",            # hex digest, H≈3.64 < 4.0
        "arn:aws:iam::123456789012:role/app",          # not token charset (':' '/')
        "https://prod.example.com/v1/ingest",          # URL, not token charset
        "ami-0abcdef1234567890",                       # cloud resource-id prefix
        "vpc-0123456789abcdef0",                       # cloud resource-id prefix
        "${var.api_token}",                            # interpolation
        "my-app-production-logs-bucket-name",          # readable, low entropy
        "550e8400-e29b-41d4-a716-446655440000",        # UUID, H≈3.39 < 4.0
    ])
    def test_non_secrets_ignored(self, v):
        assert not H._is_high_entropy_secret(v, min_len=20, max_len=100, min_entropy=4.0)

    def test_max_length_excludes_blobs(self):
        # A long base64 blob (cert / user_data) is not a token — over max_len.
        blob = "QQ" + "kT9xQ2mZ7pL4vR8nW1cF3hJ6dS5gB0yA7zX" * 5
        assert len(blob) > 100
        assert not H._is_high_entropy_secret(blob, min_len=20, max_len=100, min_entropy=4.0)


class TestHandler:
    def test_fires_on_oddly_named_field_with_correct_location(self):
        tf = (
            'resource "aws_instance" "app" {\n'
            '  ami         = "ami-0abcdef1234567890"\n'
            f'  session_key = "{TOKEN}"\n'
            "}\n"
        )
        findings = H._detect_high_entropy_string(_ctx(tf))
        assert len(findings) == 1
        f = findings[0]
        assert f["id"] == "SEC-SECRETS-ENTROPY-001"
        assert f["resource"] == "aws_instance.app"
        assert f["line"] == 3
        assert "session_key" in f["context"]

    def test_silent_on_excluded_values(self):
        tf = (
            'resource "aws_instance" "app" {\n'
            '  ami        = "ami-0abcdef1234567890"\n'
            '  region     = "us-east-1"\n'
            '  commit_sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709"\n'
            "  api_token  = var.api_token\n"
            "}\n"
        )
        assert H._detect_high_entropy_string(_ctx(tf)) == []

    def test_threshold_is_configurable(self):
        tf = f'resource "x" "y" {{\n  k = "{TOKEN}"\n}}\n'
        # default 4.0 → fires; raise above the token's 4.61 → no fire.
        assert len(H._detect_high_entropy_string(_ctx(tf))) == 1
        assert H._detect_high_entropy_string(_ctx(tf, {"min_entropy": 5.0})) == []

    def test_commented_out_secret_not_flagged(self):
        tf = (
            'resource "x" "y" {\n'
            f'  # leaked = "{TOKEN}"\n'
            '  k = "ok"\n'
            "}\n"
        )
        assert H._detect_high_entropy_string(_ctx(tf)) == []
