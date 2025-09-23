# rt_evade (PE Evasion Toolkit)

Authorized-lab PE static-ML evasion toolkit. PE-in, PE-out. PE-aware obfuscation with mimicry capabilities.

- Set `REDTEAM_MODE=true` to enable.
- File writes require `ALLOW_ACTIONS=true`.
- PE-specific obfuscation with benign software mimicry.

Quick start

```bash
# With Makefile (recommended)
make help             # show all targets
make run              # PE obfuscation with mimicry, writes to out/out.bin
make run-pe           # PE obfuscation with all features enabled
make dry-run          # no file writes, just show what would be done
make dropper          # execute an obfuscated PE at runtime
make embed            # embed obfuscated PE into Python module
make bundle           # build single executable dropper (PyInstaller onefile)
make single           # one-shot: clean→embed→bundle to out/dropper
make clean            # remove all build artifacts

# Override variables
make single INPUT=path/to/payload.exe

# Direct CLI (manual env)
export REDTEAM_MODE=true
python -m src transform path/to/payload.exe --pe-obfuscate --pe-mimicry --pe-strings --output out/out.exe
# Execute via dropper (runtime decode to temp file)
REDTEAM_MODE=true ALLOW_ACTIONS=true python -m src dropper out/out.exe
```

Subpackages
- `rt_evade.core`: guards, transform plans, pipeline.
- `rt_evade.pe`: PE-specific obfuscation and manipulation.
  - `reader`: PE file parsing and analysis.
  - `writer`: PE file modification while preserving structure.
  - `validator`: PE format validation and integrity checking.
  - `mimicry`: Benign software template matching and characteristic copying.
  - `obfuscator`: Multi-layer PE-aware obfuscation engine.
- `rt_evade.dropper`: runtime decode helpers for in-memory reversal.
  - Includes `embed` and `standalone` for single-binary workflows.

Notes
- Keep a transformation ledger via logs; avoid decoding to disk.
- Respect ROE; this is a research lab tool, not for unauthorized use.
- PE obfuscation uses mimicry to make files look like benign software.
- Output PE files are obfuscated at rest and will not run directly; execute them via the dropper which decodes in-memory to a temporary executable.

Makefile
- Condensed targets: `run`, `run-pe`, `dry-run`, `dropper`, `embed`, `bundle`, `single`, `clean`, `test`.
- Environment set automatically: `REDTEAM_MODE=true`, `ALLOW_ACTIONS=true`, `LOG_LEVEL`.
- Variables (override via `make VAR=value`):
  - `INPUT` (path to input PE file; default `samples/sample.bin`)
  - `OUTPUT` (default `out/out.bin`)
  - `LOG_LEVEL` (default `INFO`)
- `make clean` removes: `out/`, `build/`, `dist/`, `*.spec`, `__pycache__/`, `.pytest_cache/`

Testing
- Dev deps: `pip install -r requirements.txt`
- Run tests: `make test` (sets `REDTEAM_MODE=true`, `PYTHONPATH=src`) or `pytest -vv -s`
- The test suite validates PE obfuscation functionality including:
  - PE file reading, writing, and validation
  - Mimicry engine template matching
  - Multi-layer obfuscation with string obfuscation and section padding
  - PE format integrity after transformations

Single-binary workflow (PE only)

```bash
# One-shot build (no env needed at runtime)
make single INPUT=path/to/payload.exe

# Execute single binary (no env vars required)
./out/dropper
```

## PE Obfuscation Features

### Mimicry
- Template matching against benign software characteristics
- Copies section names, import tables, and header metadata
- Supports categories: system utilities, web browsers, office applications

### String Obfuscation
- Identifies and obfuscates suspicious strings in PE sections
- Uses Base64 encoding to hide malicious string patterns
- Preserves PE structure while concealing content

### Section Manipulation
- Adds junk data to increase entropy
- Injects payloads into existing sections
- Modifies section characteristics to appear benign

### Validation
- Comprehensive PE format validation
- Ensures output files maintain PE integrity
- Validates execution compatibility after obfuscation
