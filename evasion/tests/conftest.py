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


@pytest.fixture(scope="session")
def hello_bin(project_root: Path) -> Path:
    assets = project_root / "tests" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    src = assets / "hello.cpp"
    if not src.exists():
        src.write_text('#include <iostream>\nint main(){ std::cout << "Hello, World!"; return 0; }\n')
    out = assets / "hello-world"
    # Compile with g++ if available
    try:
        subprocess.run(["g++", str(src), "-O2", "-o", str(out)], check=True, capture_output=True)
    except FileNotFoundError:
        pytest.skip("g++ not available in environment")
    return out


# No autouse fixture needed for sys.path; we set it at import time above.


