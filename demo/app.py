"""tf-analyze interactive web demo backend."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="tf-analyze demo", docs_url=None, redoc_url=None)

DETECT = Path(__file__).parent.parent / "scripts" / "detect.py"
CATALOG = Path(__file__).parent.parent / "catalog"

_rate: dict[str, list[float]] = defaultdict(list)


def _rate_check(ip: str) -> bool:
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < 60]
    if len(_rate[ip]) >= 10:
        return False
    _rate[ip].append(now)
    return True


class ScanHcl(BaseModel):
    hcl: str


class ScanRepo(BaseModel):
    repo: str


def _run_scan(target_dir: str) -> dict:
    result = subprocess.run(
        [
            "python3", str(DETECT),
            "--target", target_dir,
            "--catalog", str(CATALOG),
            "--format", "json",
            "--attack-graph",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Scanner returned invalid JSON")


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (Path(__file__).parent / "index.html").read_text()


@app.post("/scan/hcl")
async def scan_hcl(body: ScanHcl, request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    if len(body.hcl) > 50_000:
        raise HTTPException(status_code=400, detail="HCL too large (max 50 KB)")
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "main.tf").write_text(body.hcl)
        return _run_scan(d)


@app.post("/scan/repo")
async def scan_repo(body: ScanRepo, request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (10 req/min)")
    url = body.repo.strip()
    if not re.match(r"https://(github|gitlab)\.com/[\w.\-]+/[\w.\-]+(\.git)?$", url):
        raise HTTPException(status_code=400, detail="Only github.com and gitlab.com repos are supported")
    with tempfile.TemporaryDirectory() as d:
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, d],
            capture_output=True,
            timeout=30,
        )
        if clone.returncode != 0:
            raise HTTPException(status_code=400, detail="Could not clone repository")
        return _run_scan(d)
