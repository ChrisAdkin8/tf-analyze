"""A crash is an error (exit 2), not "findings found" (exit 1).

Exit codes are 0 clean, 1 findings at or above --fail-on, 2 error. Python
exits 1 on an uncaught exception, so every crash used to pass for a findings
result. Malformed plan / state JSON crashed the plan walker that way, and one
bad frame (bad JSON or a JSON array) ended the language server.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DETECT = REPO_ROOT / "scripts" / "detect.py"
sys.path.insert(0, str(Path(__file__).parent))

from test_lsp_server import LspClient, _initialize


def test_an_unexpected_exception_exits_2(monkeypatch, capsys) -> None:
    import detect

    def boom() -> None:
        raise RuntimeError("simulated bug")

    monkeypatch.setattr(detect, "_main", boom)
    with pytest.raises(SystemExit) as exc:
        detect.main()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "RuntimeError: simulated bug" in err and "internal error" in err


def test_deliberate_exits_pass_through(monkeypatch) -> None:
    import detect

    monkeypatch.setattr(detect, "_main", lambda: sys.exit(1))
    with pytest.raises(SystemExit) as exc:
        detect.main()
    assert exc.value.code == 1


@pytest.mark.parametrize(
    "plan",
    [
        {"planned_values": {"root_module": {"resources": [1, "x", None]}}},
        {
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "type": "aws_s3_bucket",
                            "name": "b",
                            "mode": "managed",
                            "values": [],
                        }
                    ]
                }
            }
        },
        {
            "planned_values": {
                "root_module": {"child_modules": {"a": 1}, "resources": None}
            }
        },
        {"planned_values": {"root_module": {"child_modules": [1, {"resources": "x"}]}}},
        {"planned_values": [1, 2]},
        {"planned_values": {"root_module": [1]}},
    ],
)
def test_malformed_plan_json_does_not_crash(tmp_path: Path, plan: dict) -> None:
    (tmp_path / "plan.json").write_text(json.dumps(plan))
    target = tmp_path / "t"
    target.mkdir()
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--plan-json",
            str(tmp_path / "plan.json"),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 0
    json.loads(proc.stdout)


def test_malformed_state_json_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "state.json").write_text(
        json.dumps({"values": {"root_module": {"resources": [7]}}})
    )
    target = tmp_path / "t"
    target.mkdir()
    proc = subprocess.run(
        [
            sys.executable,
            str(DETECT),
            "--target",
            str(target),
            "--state-json",
            str(tmp_path / "state.json"),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "Traceback" not in proc.stderr, proc.stderr
    assert proc.returncode == 0


def _raw(lsp: LspClient, body: bytes) -> None:
    assert lsp.proc.stdin is not None
    lsp.proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    lsp.proc.stdin.flush()


@pytest.mark.parametrize(
    ("body", "code"),
    [(b"{not json", -32700), (b"[1, 2]", -32600), (b'"just a string"', -32600)],
)
def test_lsp_answers_a_bad_frame_and_keeps_running(body: bytes, code: int) -> None:
    with LspClient() as lsp:
        _initialize(lsp)
        _raw(lsp, body)
        err = lsp.read_until(lambda m: "error" in m and m.get("id") is None)
        assert err["error"]["code"] == code
        # Still serving: a normal request gets its answer.
        rid = lsp.send_request("shutdown")
        assert lsp.read_response(rid)["result"] is None


def test_lsp_skips_a_header_without_content_length() -> None:
    with LspClient() as lsp:
        _initialize(lsp)
        assert lsp.proc.stdin is not None
        lsp.proc.stdin.write(b"X-Junk: 1\r\n\r\n")
        lsp.proc.stdin.flush()
        rid = lsp.send_request("shutdown")
        assert lsp.read_response(rid)["result"] is None
