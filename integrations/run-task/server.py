"""HCP Terraform Run Task server for tf-analyze.

A Run Task is a webhook HCP Terraform invokes between plan and apply.
The webhook receives the plan-JSON URL, downloads it, runs detect.py
in plan-aware mode, and POSTs the result back to a callback URL.

Wire-up (in HCP Terraform / Terraform Enterprise):
  1. Settings → Run Tasks → Create
  2. Endpoint URL: https://<your-host>/runtask
  3. HMAC key: any 32-byte hex; set the same value in TFA_RUN_TASK_HMAC_KEY here
  4. Attach the run task to a workspace; choose enforcement level
     (advisory or mandatory)

Local smoke test:
  pip install fastapi uvicorn requests
  TFA_RUN_TASK_HMAC_KEY=00000000000000000000000000000000 \
    uvicorn server:app --port 8000

Then send a fake payload (HMAC headers checked when key is set):
  curl -X POST http://localhost:8000/runtask \
    -H 'Content-Type: application/json' \
    -d @sample-payload.json
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import subprocess
import sys
import tempfile
from hashlib import sha512
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import JSONResponse
    import requests  # type: ignore
except ImportError:  # pragma: no cover
    print(
        "ERROR: this stub needs `pip install fastapi uvicorn requests`. "
        "Kept as an optional dep so the core CLI stays stdlib-only.",
        file=sys.stderr,
    )
    raise

LOG = logging.getLogger("tf-analyze.runtask")
logging.basicConfig(level=os.environ.get("TFA_LOG_LEVEL", "INFO"))

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECT_PY = REPO_ROOT / "scripts" / "detect.py"
HMAC_KEY = os.environ.get("TFA_RUN_TASK_HMAC_KEY", "").encode()
FAIL_ON = os.environ.get("TFA_RUN_TASK_FAIL_ON", "HIGH")

app = FastAPI(title="tf-analyze HCP Terraform Run Task")

URGENCY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _verify_hmac(body: bytes, header: str | None) -> bool:
    """HCP Terraform sends X-Tfc-Task-Signature: sha512=hex(hmac).

    When TFA_RUN_TASK_HMAC_KEY is unset we accept all requests (dev-only).
    """
    if not HMAC_KEY:
        LOG.warning("HMAC verification disabled — set TFA_RUN_TASK_HMAC_KEY in prod")
        return True
    if not header or not header.startswith("sha512="):
        return False
    expected = hmac.new(HMAC_KEY, body, sha512).hexdigest()
    return hmac.compare_digest(expected, header[7:])


def _run_detect(plan_json_path: Path) -> tuple[list[dict], int]:
    """Invoke detect.py in plan-aware mode against the downloaded plan.

    Returns (findings, exit_code). exit_code 0 = clean, 1 = fail-on hit.
    """
    cmd = [
        sys.executable, str(DETECT_PY),
        "--target", str(plan_json_path.parent),
        "--plan-json", str(plan_json_path),
        "--format", "json",
        "--fail-on", FAIL_ON,
        "--no-hcl2",  # plan path doesn't need heredoc parser
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if res.stderr:
        LOG.info("detect.py stderr: %s", res.stderr.strip())
    try:
        data = json.loads(res.stdout)
        findings = data.get("findings", [])
    except json.JSONDecodeError:
        LOG.error("detect.py did not return JSON: %s", res.stdout[:500])
        findings = []
    return findings, res.returncode


def _format_status_body(findings: list[dict], threshold: str) -> dict:
    """Build the HCP Run Task callback payload."""
    breach = [
        f for f in findings
        if URGENCY_RANK.get(f.get("urgency", "LOW"), 0)
        >= URGENCY_RANK.get(threshold, 3)
    ]
    status = "failed" if breach else "passed"
    counts = {u: sum(1 for f in findings if f.get("urgency") == u) for u in URGENCY_RANK}
    summary = (
        f"tf-analyze: {len(findings)} finding(s) "
        f"(C:{counts['CRITICAL']} H:{counts['HIGH']} "
        f"M:{counts['MEDIUM']} L:{counts['LOW']}). "
        f"{'Blocked' if breach else 'No'} {threshold}+ findings."
    )
    return {
        "data": {
            "type": "task-results",
            "attributes": {
                "status": status,
                "message": summary,
                "url": "",  # add a public report URL once HTML hosting is wired
            },
        },
    }


@app.post("/runtask")
async def run_task(request: Request) -> JSONResponse:
    body = await request.body()
    signature = request.headers.get("x-tfc-task-signature")
    if not _verify_hmac(body, signature):
        raise HTTPException(status_code=401, detail="invalid HMAC signature")

    payload: dict[str, Any] = json.loads(body or b"{}")
    LOG.info("run-task payload received: stage=%s task=%s", payload.get("stage"),
             payload.get("task_result_id"))

    # Test/verification ping — HCP sends `access_token = "test-token"` and a
    # `payload_version` field. Reply 200 immediately.
    if payload.get("access_token") == "test-token":
        return JSONResponse({"data": {"type": "task-results",
                                      "attributes": {"status": "passed",
                                                     "message": "tf-analyze ready"}}})

    plan_url = payload.get("plan_json_api_url")
    callback_url = payload.get("task_result_callback_url")
    access_token = payload.get("access_token", "")
    if not plan_url or not callback_url:
        raise HTTPException(status_code=400, detail="missing plan_json_api_url or callback_url")

    headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
    plan_resp = requests.get(plan_url, headers=headers, timeout=30)
    if plan_resp.status_code != 200:
        LOG.error("plan download failed: %s", plan_resp.status_code)
        raise HTTPException(status_code=502, detail="cannot fetch plan-json")

    with tempfile.TemporaryDirectory() as td:
        plan_path = Path(td) / "plan.json"
        plan_path.write_bytes(plan_resp.content)
        findings, _ = _run_detect(plan_path)

    callback_body = _format_status_body(findings, FAIL_ON)
    cb = requests.patch(
        callback_url,
        headers={**headers, "Content-Type": "application/vnd.api+json"},
        data=json.dumps(callback_body),
        timeout=10,
    )
    if cb.status_code >= 300:
        LOG.warning("callback returned %s: %s", cb.status_code, cb.text[:200])
    return JSONResponse({"received": len(findings)})


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "detect_py": DETECT_PY.exists()}
