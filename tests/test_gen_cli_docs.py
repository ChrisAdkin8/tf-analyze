"""`gen-cli-docs.py --check` reads detect.py's parser without a crash.

The script stops `detect.main()` at `parse_args` by raising its own
exception. When `main()` started turning every `Exception` into a printed
traceback and exit 2 (#103), it caught that one too: `--check` still
passed, but printed an "internal error" traceback on every run.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

GEN = Path(__file__).resolve().parents[1] / "scripts" / "gen-cli-docs.py"


def test_check_runs_clean() -> None:
    proc = subprocess.run(
        [sys.executable, str(GEN), "--check"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr
    assert "internal error" not in proc.stderr, proc.stderr
