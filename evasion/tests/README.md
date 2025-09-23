# Tests

This suite validates PE obfuscation functionality and format integrity.

## Setup

- Python 3.10+
- Install dev deps:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Note: requirements.txt includes pytest, pyinstaller, and pefile
```

- PE file format support via pefile library
- Cross-platform (Windows, Linux, macOS)

## What the tests do

- **PE Reader Tests**: Validate PE file parsing, header extraction, section analysis, and import table reading
- **PE Writer Tests**: Test PE file modification, section addition, string replacement, and payload injection
- **PE Validator Tests**: Ensure PE format validation, execution compatibility checking, and error detection
- **PE Mimicry Tests**: Verify template matching, characteristic copying, and benign software mimicry
- **PE Obfuscator Tests**: Test multi-layer obfuscation including string obfuscation, section padding, and entropy increase
- **Integration Tests**: Validate complete PE obfuscation pipeline and format integrity

## Running

```bash
make test
# or
pytest -vv -s
```

Notes on environment:
- `make test` sets `REDTEAM_MODE=true`, `PYTHONPATH=src` automatically.
- PE obfuscation tests use mock PE data for cross-platform compatibility.
- Build artifacts are cleaned with `make clean` (removes `out/`, `build/`, `dist/`, `*.spec`, `__pycache__/`, `.pytest_cache/`).

## Test Structure

### Test Files
- `test_pe_obfuscation.py`: Comprehensive PE obfuscation test suite
- `conftest.py`: Test fixtures and environment setup

### Test Categories
- **Unit Tests**: Individual component testing (reader, writer, validator, mimicry, obfuscator)
- **Integration Tests**: End-to-end PE obfuscation pipeline testing
- **Mock Data**: Uses synthetic PE data for cross-platform compatibility

## Troubleshooting

- **Missing pefile**: Install with `pip install pefile>=2023.2.7`
- **Permission issues**: Ensure workspace allows file operations
- **Test failures**: Check that `REDTEAM_MODE=true` is set in environment
