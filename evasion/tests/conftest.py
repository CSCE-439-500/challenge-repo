import os
import subprocess
import sys
from pathlib import Path

import pytest

# Ensure the package under src is importable during test collection
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_PATH = str(_PROJECT_ROOT / "src")
if _SRC_PATH not in sys.path:
    sys.path.insert(0, _SRC_PATH)


@pytest.fixture(scope="session")
def project_root() -> Path:
    return _PROJECT_ROOT


@pytest.fixture(scope="session")
def ensure_env() -> None:
    os.environ.setdefault("REDTEAM_MODE", "true")
    os.environ.setdefault("LOG_LEVEL", "INFO")
