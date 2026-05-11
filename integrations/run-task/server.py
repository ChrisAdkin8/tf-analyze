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

# Optional compliance-framework gating. When set the engine renders a
# compliance gap report against the named framework alongside its
# findings; the callback message gains a compact `compliance: …` line so
# the operator sees the framework posture in the run-task UI without
# digging into the engine's JSON.
_VALID_FRAMEWORKS = {"cis", "pci_dss", "soc2", "owasp_iac", "all"}
COMPLIANCE_FRAMEWORK = os.environ.get("TFA_RUN_TASK_FRAMEWORK", "").strip()
if COMPLIANCE_FRAMEWORK and COMPLIANCE_FRAMEWORK not in _VALID_FRAMEWORKS:
    LOG.error(
        "ignoring TFA_RUN_TASK_FRAMEWORK=%r; expected one of %s",
        COMPLIANCE_FRAMEWORK, sorted(_VALID_FRAMEWORKS),
    )
    COMPLIANCE_FRAMEWORK = ""

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


def _run_detect(plan_json_path: Path) -> tuple[dict, int]:
    """Invoke detect.py in plan-aware mode against the downloaded plan.

    Returns (engine_payload, exit_code). exit_code 0 = clean, 1 = fail-on
    hit. The full engine JSON is returned so the callback message can
    include compliance-framework counts when one is configured.
    """
    cmd = [
        sys.executable, str(DETECT_PY),
        "--target", str(plan_json_path.parent),
        "--plan-json", str(plan_json_path),
        "--format", "json",
        "--fail-on", FAIL_ON,
        "--no-hcl2",  # plan path doesn't need heredoc parser
    ]
    if COMPLIANCE_FRAMEWORK:
        cmd.extend(["--compliance-framework", COMPLIANCE_FRAMEWORK])
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if res.stderr:
        # Audit follow-up #13 — escalate stderr containing a Python
        # traceback to ERROR level so it shows up in oncall logs
        # even when the worker silently passes the result through.
        if "Traceback (most recent call last)" in res.stderr:
            LOG.error("detect.py emitted a traceback: %s", res.stderr.strip())
        else:
            LOG.info("detect.py stderr: %s", res.stderr.strip())
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        LOG.error(
            "detect.py did not return JSON (exit %d): %s",
            res.returncode, res.stdout[:500],
        )
        # Audit follow-up #13 — surface the parse failure as a synthetic
        # finding so the downstream summary doesn't render "0 findings"
        # for a scan that actually crashed.
        #
        # Round-3 audit fix #17 — emit a real finding entry (with a
        # sentinel rule-id `SYN-SCAN-FAILED`) so downstream renderers
        # (Slack notifier, the dashboard, the run-task callback body)
        # surface the failure through their normal "render each
        # finding" pipeline. The `_scan_failed: True` flag is kept for
        # backwards-compat with anything that already special-cases
        # it; new consumers should match on `id == "SYN-SCAN-FAILED"`.
        data = {
            "findings": [
                {
                    "id": "SYN-SCAN-FAILED",
                    "urgency": "CRITICAL",
                    "title": "tf-analyze engine crashed",
                    "section": "engine",
                    "file": "(engine)",
                    "line": 0,
                    "recommendation": (
                        "The engine returned non-JSON. Check the run-task "
                        "logs for the captured stderr. Most common causes: "
                        "missing catalogue, malformed .tf file, OOM."
                    ),
                    "context": res.stderr[:2000] or "(empty stderr)",
                },
            ],
            "summary": {
                "score": 0,
                "grade": "F",
                "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            },
            "_scan_failed": True,
            "_stderr": res.stderr[:2000],
        }
    return data, res.returncode


def _compliance_summary(data: dict, framework: str) -> str:
    """Render `compliance: <fw> <fail>/<total> failing` from engine JSON.

    Returns the empty string when no compliance section is present (e.g.
    framework unset, or an older engine). Walks `data["compliance"]`
    which is the engine's per-framework gap report — same shape used by
    the text/HTML/OSCAL emitters.
    """
    section = data.get("compliance") or {}
    if not section:
        return ""
    total = 0
    failing = 0
    for _fw, controls in section.items():
        if not isinstance(controls, list):
            continue
        for ctrl in controls:
            total += 1
            if ctrl.get("status") == "FAIL":
                failing += 1
    if total == 0:
        return ""
    return f"compliance: {framework} {failing}/{total} controls failing."


def _format_status_body(data: dict, threshold: str) -> dict:
    """Build the HCP Run Task callback payload from the engine JSON."""
    findings = data.get("findings") or []
    breach = [
        f for f in findings
        if URGENCY_RANK.get(f.get("urgency", "LOW"), 0)
        >= URGENCY_RANK.get(threshold, 3)
    ]
    status = "failed" if breach else "passed"
    counts = {u: sum(1 for f in findings if f.get("urgency") == u) for u in URGENCY_RANK}
    parts = [
        f"tf-analyze: {len(findings)} finding(s) "
        f"(C:{counts['CRITICAL']} H:{counts['HIGH']} "
        f"M:{counts['MEDIUM']} L:{counts['LOW']}). "
        f"{'Blocked' if breach else 'No'} {threshold}+ findings.",
    ]
    if COMPLIANCE_FRAMEWORK:
        compliance_line = _compliance_summary(data, COMPLIANCE_FRAMEWORK)
        if compliance_line:
            parts.append(compliance_line)
    return {
        "data": {
            "type": "task-results",
            "attributes": {
                "status": status,
                "message": " ".join(parts),
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
        data, _ = _run_detect(plan_path)

    findings = data.get("findings") or []
    callback_body = _format_status_body(data, FAIL_ON)
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
