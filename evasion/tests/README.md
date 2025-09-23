# Tests

This suite validates runtime parity after obfuscation.

## Setup

- Python 3.10+
- Install dev deps:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
```

- A C++ compiler (`g++`) on PATH for building the sample binary.
- POSIX environment (Linux/macOS). The parity test is skipped on Windows.

## What the tests do

- Build `hello-world` from `tests/assets/hello.cpp`.
- Run baseline: expect stdout `Hello, World!`.
- Apply Base64 strings + XOR pack transforms in-memory.
- Reverse obfuscation at runtime (in-memory) and execute decoded temp binary.
- Assert stdout matches baseline.

## Running

```bash
make test
# or
pytest -vv -s
```

Notes on environment:
- `make test` sets `REDTEAM_MODE=true` and `PYTHONPATH=src` automatically.
- You can also export `REDTEAM_MODE=true` manually when using plain `pytest`.

## Troubleshooting

- Missing `g++`: install build-essential (Debian/Ubuntu) or Xcode CLI tools (macOS).
- Permission denied running temp binary: ensure the workspace allows `chmod` and exec.
