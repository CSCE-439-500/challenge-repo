# Rust-Crypter Integration

This document describes the integration of the [Rust-Crypter](https://github.com/Amaop/Rust-Crypter) tool into the rt_evade toolkit for advanced PE encryption and in-memory execution.

## Overview

The Rust-Crypter integration provides:

- **Advanced PE Encryption**: Uses Rust-Crypter's encryption capabilities
- **In-Memory Execution**: Stubs that decrypt and execute payloads in memory using memexec
- **Anti-VM Features**: Built-in virtual machine detection
- **Cross-Architecture Support**: Both x86 and x64 Windows targets
- **Automatic Compilation**: Handles Rust compilation and linking

## Prerequisites

### 1. Rust Toolchain
Install Rust from [rustup.rs](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Windows Targets
Install the required Windows targets:

```bash
rustup target add x86_64-pc-windows-gnu
rustup target add i686-pc-windows-gnu
```

### 3. Rust-Crypter Setup
Use the provided setup script:

```bash
python setup_rust_crypter.py
```

Or manually clone and set up:

```bash
git clone https://github.com/Amaop/Rust-Crypter.git rust-crypter
export RUST_CRYPTER_PATH=$(pwd)/rust-crypter
```

## Usage

### Command Line Interface

#### Basic Usage
```bash
# Set required environment variables
export REDTEAM_MODE=true
export ALLOW_ACTIONS=true

# Encrypt a PE file and generate stub
python -m src.rt_evade rust-crypter samples/out.bin
```

#### Advanced Usage
```bash
# Custom output path and configuration
python -m src.rt_evade rust-crypter samples/out.bin \
    --output encrypted_payload.exe \
    --target-arch x86_64-pc-windows-gnu \
    --build-mode release \
    --rust-crypter-path /path/to/Rust-Crypter

# Disable anti-VM features
python -m src.rt_evade rust-crypter samples/out.bin \
    --no-anti-vm

# Set custom file size limit
python -m src.rt_evade rust-crypter samples/out.bin \
    --max-file-size 10485760  # 10MB
```

### Programmatic Usage

```python
import os
from pathlib import Path
from rt_evade.dropper.rust_crypter import RustCrypterIntegration, RustCrypterConfig

# Set required environment variables
os.environ["REDTEAM_MODE"] = "true"
os.environ["ALLOW_ACTIONS"] = "true"

# Load PE file
pe_data = Path("samples/out.bin").read_bytes()

# Create configuration
config = RustCrypterConfig(
    rust_crypter_path="/path/to/Rust-Crypter",  # Optional: auto-detect
    target_architecture="x86_64-pc-windows-gnu",
    build_mode="release",
    anti_vm=True,
    max_file_size=5 * 1024 * 1024,  # 5MB
)

# Initialize integration
rust_crypter = RustCrypterIntegration(config)

# Create encrypted payload with stub
stub_path = rust_crypter.create_encrypted_payload(pe_data, Path("output.exe"))

# Generate report
report = rust_crypter.get_encryption_report(pe_data, b"", stub_path)
print(f"Stub size: {report['stub_size']} bytes")
print(f"Compression ratio: {report['compression_ratio']:.2f}%")
```

## Configuration Options

### RustCrypterConfig

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_rust_crypter` | bool | True | Enable Rust-Crypter integration |
| `rust_crypter_path` | str | None | Path to Rust-Crypter directory (auto-detect if None) |
| `target_architecture` | str | "x86_64-pc-windows-gnu" | Rust target architecture |
| `build_mode` | str | "release" | Build mode (release/debug) |
| `anti_vm` | bool | True | Enable anti-VM features |
| `max_file_size` | int | 5MB | Maximum input file size |

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--output` | Output stub executable path |
| `--rust-crypter-path` | Path to Rust-Crypter directory |
| `--target-arch` | Target architecture (x86_64-pc-windows-gnu, i686-pc-windows-gnu) |
| `--build-mode` | Build mode (release, debug) |
| `--no-anti-vm` | Disable anti-VM features |
| `--max-file-size` | Maximum file size in bytes |

## Workflow

### 1. Encryption Process
1. **Validation**: Check PE file size and format
2. **Encryption**: Use Rust-Crypter to encrypt the PE file
3. **Key Generation**: Generate encryption key
4. **File Generation**: Create `encrypted_bytes.bin` and `key.txt`

### 2. Stub Generation
1. **Stub Creation**: Generate Rust stub source code
2. **Payload Embedding**: Embed encrypted payload and key
3. **Compilation**: Compile stub using Rust toolchain
4. **Output**: Generate final executable stub

### 3. Runtime Execution
1. **Anti-VM Check**: Detect virtual machine environment
2. **Decryption**: Decrypt payload in memory
3. **Execution**: Execute decrypted payload using memexec
4. **Cleanup**: Clean up memory artifacts

## Integration with Existing Pipeline

The Rust-Crypter integration fits into the existing rt_evade pipeline as follows:

```
Input PE File
       │
       ▼
┌─────────────────┐
│  PE Obfuscation │ ◄── Apply existing obfuscation techniques
│  (Optional)     │     • Mimicry, string obfuscation, etc.
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Rust-Crypter   │ ◄── Advanced encryption and stub generation
│  Integration    │     • Encrypt PE file
│                 │     • Generate in-memory execution stub
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Final Stub     │ ◄── Executable with encrypted payload
│  (Executable)   │     • In-memory decryption
│                 │     • Anti-VM features
└─────────────────┘
```

## Examples

### Example 1: Basic Encryption
```bash
# Encrypt a PE file
python -m src.rt_evade rust-crypter samples/out.bin --output malware.exe
```

### Example 2: With PE Obfuscation
```bash
# First apply PE obfuscation, then encrypt
python -m src.rt_evade transform samples/out.bin --output obfuscated.exe
python -m src.rt_evade rust-crypter obfuscated.exe --output final.exe
```

### Example 3: Custom Configuration
```python
from rt_evade.dropper.rust_crypter import RustCrypterIntegration, RustCrypterConfig

config = RustCrypterConfig(
    target_architecture="i686-pc-windows-gnu",  # 32-bit
    build_mode="debug",  # Debug symbols
    anti_vm=False,  # Disable anti-VM
    max_file_size=10 * 1024 * 1024,  # 10MB limit
)

rust_crypter = RustCrypterIntegration(config)
stub_path = rust_crypter.create_encrypted_payload(pe_data)
```

## Troubleshooting

### Common Issues

1. **Rust not found**
   ```
   Error: Rust toolchain not found. Please install Rust.
   ```
   **Solution**: Install Rust from [rustup.rs](https://rustup.rs/)

2. **Target not installed**
   ```
   Error: Target x86_64-pc-windows-gnu not installed
   ```
   **Solution**: Run `rustup target add x86_64-pc-windows-gnu`

3. **Rust-Crypter not found**
   ```
   Error: Rust-Crypter not found. Please set RUST_CRYPTER_PATH
   ```
   **Solution**: Run `python setup_rust_crypter.py` or set `RUST_CRYPTER_PATH`

4. **File too large**
   ```
   Error: File too large: 10485760 bytes > 5242880 bytes
   ```
   **Solution**: Increase `--max-file-size` or compress the input file

5. **Compilation failed**
   ```
   Error: Rust-Crypter stub compilation failed
   ```
   **Solution**: Check Rust installation and target availability

### Debug Mode

Enable debug mode for more verbose output:

```bash
export LOG_LEVEL=DEBUG
python -m src.rt_evade rust-crypter samples/out.bin
```

## Security Considerations

- **ROE Compliance**: All operations require `REDTEAM_MODE=true`
- **File Operations**: Require `ALLOW_ACTIONS=true` for file writes
- **Memory Safety**: Decryption occurs in memory, not on disk
- **Cleanup**: Temporary files are automatically cleaned up
- **Audit Trail**: All operations are logged for compliance

## Performance

- **Encryption Speed**: ~1-5 seconds for typical PE files
- **Stub Compilation**: ~10-30 seconds (first time), ~5-10 seconds (cached)
- **Memory Usage**: Minimal overhead during encryption
- **Output Size**: Stub size typically 2-5x original PE size

## Limitations

- **File Size**: Maximum 5MB input files (configurable)
- **Architecture**: Windows PE files only
- **Dependencies**: Requires Rust toolchain and Rust-Crypter
- **Platform**: Works on Linux, macOS, and Windows (for compilation)

## References

- [Rust-Crypter GitHub Repository](https://github.com/Amaop/Rust-Crypter)
- [Rust Installation Guide](https://rustup.rs/)
- [memexec Crate](https://crates.io/crates/memexec)
- [MITRE TTPs](https://attack.mitre.org/techniques/T1204/002/)
