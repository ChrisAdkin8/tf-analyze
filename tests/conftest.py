"""pytest configuration — shared fixtures loaded automatically."""
from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).parent
REPO_ROOT = TESTS_DIR.parent

sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
