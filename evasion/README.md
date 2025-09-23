# rt_evade (lab toolkit)

Authorized-lab static-ML evasion toolkit. Binary-in, binary-out. In-memory transforms by default.

- Set `REDTEAM_MODE=true` to enable.
- File writes require `ALLOW_ACTIONS=true`.
- XOR key via `DECODE_KEY` when using `--xor-pack`.

Quick start

```bash
# With Makefile (recommended)
make help             # show all targets
make run              # base64 + xor, writes to out/out.bin
make run-b64          # base64 only
make run-xor          # xor only
make dry-run          # no file writes
make dropper          # decode+execute an obfuscated INPUT at runtime
make embed            # embed obfuscated PE into module
make bundle           # build single executable dropper (PyInstaller onefile)
make single           # one-shot: clean→embed(with key)→bundle to out/dropper
make clean            # remove all build artifacts

# Override variables
make single INPUT=path/to/payload.exe DECODE_KEY=secret

# Direct CLI (manual env)
export REDTEAM_MODE=true
DECODE_KEY=secret python -m src transform path/to/binary --base64-strings --xor-pack --output out/out.bin
# Execute via dropper (runtime decode to temp file)
REDTEAM_MODE=true ALLOW_ACTIONS=true DECODE_KEY=secret python -m src dropper out/out.bin
```

Subpackages
- `rt_evade.core`: guards, transform plans, pipeline.
- `rt_evade.obfuscation`: Base64 string obfuscator, XOR packer.
- `rt_evade.dropper`: runtime decode helpers for in-memory reversal.
  - Includes `embed` and `standalone` for single-binary workflows.

Notes
- Keep a transformation ledger via logs; avoid decoding to disk.
- Respect ROE; this is a research lab tool, not for unauthorized use.
 - Output binaries are obfuscated at rest and will not run directly; execute them via the dropper which decodes in-memory to a temporary executable.

Makefile
- Condensed targets: `run`, `run-b64`, `run-xor`, `dry-run`, `dropper`, `embed`, `bundle`, `single`, `clean`, `test`.
- Environment set automatically: `REDTEAM_MODE=true`, `ALLOW_ACTIONS=true`, `DECODE_KEY`, `LOG_LEVEL`.
- Variables (override via `make VAR=value`):
  - `INPUT` (path to input binary; default `samples/sample.bin`)
  - `OUTPUT` (default `out/out.bin`)
  - `DECODE_KEY` (default `secret`)
  - `LOG_LEVEL` (default `INFO`)
- `make clean` removes: `out/`, `build/`, `dist/`, `*.spec`, `__pycache__/`, `.pytest_cache/`

Testing
- Dev deps: `pip install -r requirements.txt`
- Run tests: `make test` (sets `REDTEAM_MODE=true`, `PYTHONPATH=src`) or `pytest -vv -s`
- The test suite builds a tiny C++ `hello-world` and verifies stdout parity after Base64+XOR obfuscation and in-memory decode.
 - Additional E2E test covers embedding and standalone dropper execution.

Single-binary workflow (PE only)

```bash
# One-shot build (no env needed at runtime)
make single INPUT=path/to/payload.exe DECODE_KEY=secret

# Execute single binary (no env vars required)
./out/dropper
```
