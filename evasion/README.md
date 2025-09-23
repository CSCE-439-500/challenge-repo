# rt_evade (lab toolkit)

Authorized-lab static-ML evasion toolkit. Binary-in, binary-out. In-memory transforms by default.

- Set `REDTEAM_MODE=true` to enable.
- File writes require `ALLOW_ACTIONS=true`.
- XOR key via `DECODE_KEY` when using `--xor-pack`.

Quick start

```bash
# With Makefile (recommended)
make help
make run              # base64 + xor, writes to out/out.bin
make run-b64          # base64 only
make run-xor          # xor only
make dry-run          # no file writes

# Override variables
make run INPUT=path/to/binary OUTPUT=out/custom.bin DECODE_KEY=mykey LOG_LEVEL=DEBUG

# Direct CLI (manual env)
export REDTEAM_MODE=true
DECODE_KEY=secret python -m src path/to/binary --base64-strings --xor-pack --output out/out.bin
```

Subpackages
- `rt_evade.core`: guards, transform plans, pipeline.
- `rt_evade.obfuscation`: Base64 string obfuscator, XOR packer.
- `rt_evade.dropper`: runtime decode helpers for in-memory reversal.

Notes
- Keep a transformation ledger via logs; avoid decoding to disk.
- Respect ROE; this is a research lab tool, not for unauthorized use.

Makefile
- Targets: `run`, `run-b64`, `run-xor`, `dry-run`, `clean`, `init`.
- Environment set automatically for `run*` targets: `REDTEAM_MODE=true`, `ALLOW_ACTIONS=true`, optional `DECODE_KEY`.
- Variables (override via `make VAR=value`):
  - `INPUT` (path to input binary)
  - `OUTPUT` (default `out/out.bin`)
  - `DECODE_KEY` (required for XOR paths; default `secret`)
  - `LOG_LEVEL` (default `INFO`)
