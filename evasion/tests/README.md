# Tests

This suite validates runtime parity after obfuscation.

## Setup

- Python 3.10+
- Install dev deps:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Note: requirements.txt includes pytest and pyinstaller
```

- A C++ compiler (`g++`) on PATH for building the sample binary.
- POSIX environment (Linux/macOS). The parity test is skipped on Windows.

## What the tests do

- Build `hello-world` from `tests/assets/hello.cpp`.
- Run baseline: expect stdout `Hello, World!`.
- Apply Base64 strings + XOR pack transforms in-memory.
- Reverse obfuscation at runtime (in-memory) and execute decoded temp binary.
- Assert stdout matches baseline.
 - E2E: Embed obfuscated payload (with embedded key) and execute via standalone dropper without any env vars.

## Running

```bash
make test
# or
pytest -vv -s
```

Notes on environment:
- `make test` sets `REDTEAM_MODE=true`, `PYTHONPATH=src` automatically.
- Single-binary runs do not require environment variables.
- Build artifacts are cleaned with `make clean` (removes `out/`, `build/`, `dist/`, `*.spec`, `__pycache__/`, `.pytest_cache/`).

## Troubleshooting

- Missing `g++`: install build-essential (Debian/Ubuntu) or Xcode CLI tools (macOS).
- Permission denied running temp binary: ensure the workspace allows `chmod` and exec.
 - For embed/bundle tests locally: ensure `DECODE_KEY` is set at build-time only and PyInstaller installed.
