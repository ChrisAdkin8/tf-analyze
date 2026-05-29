"""Security regression tests for the HCP Run Task server (P0 #1).

The webhook fetches request-supplied URLs while forwarding the caller's HCP
bearer token, so a forged/unauthenticated request used to be an SSRF +
token-relay. These tests pin the two controls added in the hardening:

  1. HMAC verification fails CLOSED when the key is unset.
  2. Outbound URLs are restricted to an allow-list of public HCP/TFE hosts.

Network-free: SSRF rejections trip on scheme/allow-list before any DNS, and
the public-IP logic is tested via `_addr_is_public` with literal addresses.

The server depends on fastapi + requests (optional deps), so the whole module
skips when they aren't installed — matching the project's optional-dep tests.
"""
from __future__ import annotations

import hmac as _hmac
import importlib.util
import os
from hashlib import sha512
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("requests")

_SERVER = Path(__file__).parent.parent / "integrations" / "run-task" / "server.py"


def _load(**env: str | None):
    """Import the server module fresh with the given env (config is read at
    import time). `None` clears a var."""
    for k, v in env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    spec = importlib.util.spec_from_file_location("_rt_server_under_test", _SERVER)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


# ---- fail-closed HMAC ------------------------------------------------------

def test_hmac_fails_closed_when_key_unset():
    m = _load(TFA_RUN_TASK_HMAC_KEY=None, TFA_RUN_TASK_ALLOW_INSECURE=None)
    assert m._verify_hmac(b"{}", None) is False
    assert m._verify_hmac(b"{}", "sha512=deadbeef") is False


def test_hmac_insecure_override_is_explicit_opt_in():
    m = _load(TFA_RUN_TASK_HMAC_KEY=None, TFA_RUN_TASK_ALLOW_INSECURE="1")
    assert m._verify_hmac(b"{}", None) is True


def test_hmac_verifies_correct_signature_with_key():
    m = _load(TFA_RUN_TASK_HMAC_KEY="s3cret", TFA_RUN_TASK_ALLOW_INSECURE=None)
    body = b'{"x":1}'
    good = "sha512=" + _hmac.new(b"s3cret", body, sha512).hexdigest()
    assert m._verify_hmac(body, good) is True
    assert m._verify_hmac(body, "sha512=00") is False
    assert m._verify_hmac(body, None) is False


# ---- SSRF guard ------------------------------------------------------------

def test_addr_is_public_rejects_private_and_metadata():
    m = _load(TFA_RUN_TASK_HMAC_KEY="s3cret")
    for bad in ["169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1",
                "172.16.0.1", "::1", "0.0.0.0", "fd00::1"]:
        assert m._addr_is_public(bad) is False, bad
    for good in ["8.8.8.8", "1.1.1.1"]:
        assert m._addr_is_public(good) is True, good


def test_validate_outbound_url_rejects_ssrf_targets():
    m = _load(TFA_RUN_TASK_HMAC_KEY="s3cret", TFA_RUN_TASK_ALLOWED_HOSTS=None)
    from fastapi import HTTPException
    for bad in [
        "http://app.terraform.io/x",                  # not https
        "https://169.254.169.254/latest/meta-data/",  # cloud metadata, not allow-listed
        "https://evil.example.com/x",                 # arbitrary host
        "https://localhost/x",                        # loopback host name
        "https://app.terraform.io.evil.com/x",        # suffix-confusion host
    ]:
        with pytest.raises(HTTPException):
            m._validate_outbound_url(bad, "plan_json_api_url")


def test_validate_outbound_url_accepts_allowlisted_public_host(monkeypatch):
    m = _load(TFA_RUN_TASK_HMAC_KEY="s3cret")
    # Avoid real DNS — pin the allow-listed host to a public IP.
    monkeypatch.setattr(
        m.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 443))],  # genuinely public
    )
    m._validate_outbound_url("https://app.terraform.io/api/v2/runs/x/plan/json", "plan")


def test_validate_outbound_url_rejects_allowlisted_host_resolving_private(monkeypatch):
    # DNS-rebind style: an allow-listed name that resolves into private space
    # is still rejected by the public-IP check.
    m = _load(TFA_RUN_TASK_HMAC_KEY="s3cret")
    from fastapi import HTTPException
    monkeypatch.setattr(
        m.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(HTTPException):
        m._validate_outbound_url("https://app.terraform.io/x", "plan")
