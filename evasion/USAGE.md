# Usage Guide

**Complete guide for using the rt_evade PE Evasion Toolkit**

- Set `REDTEAM_MODE=true` to enable.
- File writes require `ALLOW_ACTIONS=true`.
- **Modular architecture** with specialized obfuscation components.

## 🚀 Quick Start

### Local Installation

```bash
# Show all available targets
make help

# Basic PE obfuscation (mimicry + strings + imports)
make run INPUT=path/to/payload.exe

# Full PE obfuscation (all modules enabled)
# UPX packing is ON by default via Make; disable with UPX=0
make run-pe INPUT=path/to/payload.exe OUTPUT=out/obfuscated.exe

# Rust-Crypter encryption: PE obfuscation + advanced encryption
make run-crypt INPUT=path/to/payload.exe OUTPUT=out/encrypted.exe

# One-shot: embed + bundle to standalone dropper
make single INPUT=path/to/payload.exe DECODE_KEY=mykey

# Batch obfuscation: process all binaries in a folder
make batch-obfuscate INPUT_DIR=samples/ OUTPUT_DIR=out/
make batch-crypt INPUT_DIR=samples/ OUTPUT_DIR=out/  # With Rust-Crypter
make batch-dry-run INPUT_DIR=samples/  # Preview what would be processed

# Test individual modules
make test-compression
make test-encryption
make test-strings
make test-sections
make test-rust-crypter  # Test Rust-Crypter integration
```

### Docker Usage

#### Using Makefile (Recommended)

```bash
# Build the Docker image
make docker-build

# Process a single file
# Pass UPX=0 to disable packing; customize args with UPX_ARGS
make docker-run INPUT=path/to/payload.exe

# Process a directory of files (batch obfuscation)
make docker-run INPUT=samples/

# With custom output directory
make docker-run INPUT=samples/ OUTPUT_DIR=custom_output/

# With verbose logging
make docker-run INPUT=payload.exe LOG_LEVEL=DEBUG

# Clean up Docker images
make docker-clean
```

#### Direct Docker Commands

```bash
# Build the Docker image
docker build -t pe-evasion .

# Process a single file
docker run -v /path/to/input:/input -v /path/to/output:/output pe-evasion --input /input/payload.exe

# Process a directory of files
docker run -v /path/to/samples:/input -v /path/to/output:/output pe-evasion --input /input

# Custom output directory
docker run -v /path/to/samples:/input -v /path/to/output:/output pe-evasion --input /input --output-dir /output/obfuscated

# Show help
docker run pe-evasion --help
```

## 📋 Available Makefile Targets

### Main Obfuscation Targets
- `make run` - Basic PE obfuscation (mimicry + strings + imports)
- `make run-pe` - Full PE obfuscation (all modules enabled)
- `make run-crypt` - PE obfuscation + Rust-Crypter encryption
- `make dry-run` - Show obfuscation plan without file writes
- `make single` - One-shot: embed + bundle to standalone dropper
- `make batch-obfuscate` - Obfuscate all binaries in a folder
- `make batch-crypt` - Obfuscate + Rust-Crypter encrypt all binaries in a folder
- `make batch-dry-run` - Show what would be obfuscated without doing it

### Specialized Module Testing
- `make test-modules` - Test all specialized modules
- `make test-compression` - Test compression module only
- `make test-encryption` - Test encryption module only
- `make test-strings` - Test string obfuscation module only
- `make test-sections` - Test section manipulation module only
- `make test-rust-crypter` - Test Rust-Crypter integration module only

### Utility Targets
- `make test` - Run all tests (153 tests)
- `make dropper` - Execute obfuscated PE via dropper
- `make embed` - Embed PE into Python module
- `make bundle` - Create standalone executable
- `make clean` - Remove all build artifacts

### Docker Targets
- `make docker-build` - Build Docker image for PE evasion toolkit
- `make docker-run` - Run PE obfuscation in Docker container
- `make docker-clean` - Remove Docker images and containers

## 🔧 Configuration

### Environment Variables
- `REDTEAM_MODE=true` - Required to enable toolkit
- `ALLOW_ACTIONS=true` - Required for file writes
- `USE_UPX=1` - Enable UPX packing (Make passes this automatically unless `UPX=0`)
- `UPX_ARGS="--best --lzma"` - Extra flags for UPX
- `DECODE_KEY=secret` - Encryption key for runtime decoding
- `LOG_LEVEL=INFO` - Logging verbosity

### Makefile Variables
- `INPUT` - Path to input PE file (default: `samples/sample.bin`)
- `INPUT_DIR` - Directory containing binaries to obfuscate (default: `samples`)
- `OUTPUT` - Output path (default: `out/out.bin`)
- `OUTPUT_DIR` - Output directory for batch obfuscation (default: `out`)
- `DECODE_KEY` - Encryption key (default: `secret`)
- `LOG_LEVEL` - Log level (default: `INFO`)
- `UPX=1` - Enable UPX packing by default in `run`, `run-pe`, `dry-run` (set `UPX=0` to disable)
- `UPX_ARGS="--best --lzma"` - Extra flags for UPX

## 🧪 Testing

The refactored codebase includes comprehensive test coverage:

```bash
# Run all tests (134 tests)
make test

# Test individual modules
make test-modules          # All specialized modules
make test-compression      # Compression module only
make test-encryption       # Encryption module only
make test-strings          # String obfuscation only
make test-sections         # Section manipulation only

# Test with verbose output
make test LOG_LEVEL=DEBUG
```

**Test Coverage:**
- ✅ **153 tests passing** (including Rust-Crypter integration)
- ✅ **Modular test structure** with focused test files
- ✅ **Integration tests** for end-to-end workflows
- ✅ **Unit tests** for each specialized module
- ✅ **Configuration validation** for all modules
- ✅ **Rust-Crypter integration tests** for advanced encryption workflows

## 🎯 Single-Binary Workflow

```bash
# One-shot build (no env needed at runtime)
make single INPUT=path/to/payload.exe

# Execute single binary (no env vars required)
./out/dropper
```

## 📦 Batch Obfuscation Workflow

```bash
# Obfuscate all binaries in a folder
make batch-obfuscate INPUT_DIR=samples/ OUTPUT_DIR=out/

# Preview what would be processed (dry run)
make batch-dry-run INPUT_DIR=samples/

# Custom output directory
make batch-obfuscate INPUT_DIR=my_binaries/ OUTPUT_DIR=obfuscated_binaries/

# Process with verbose logging
make batch-obfuscate INPUT_DIR=samples/ LOG_LEVEL=DEBUG
```

**Batch Processing Features:**
- Automatically detects binary files by extension and content
- Preserves original filenames in output directory
- Applies full PE obfuscation to each file
- Continues processing even if individual files fail
- Provides detailed logging of success/failure counts

The output PE files are obfuscated at rest and will not run directly; execute them via the dropper which decodes in-memory to a temporary executable.

## 🔐 Rust-Crypter Advanced Encryption Workflow

The Rust-Crypter integration provides advanced PE encryption with in-memory execution capabilities:

### **Single File Processing**

```bash
# Basic Rust-Crypter encryption
make run-crypt INPUT=payload.exe OUTPUT=encrypted.exe

# With custom configuration
python -m src transform payload.exe \
  --pe-rust-crypter \
  --target-arch x86_64-pc-windows-gnu \
  --build-mode release \
  --output encrypted.exe

# With anti-VM disabled
python -m src transform payload.exe \
  --pe-rust-crypter \
  --no-anti-vm \
  --output encrypted.exe
```

### **Batch Processing with Rust-Crypter**

```bash
# Process all binaries in a folder with Rust-Crypter
make batch-crypt INPUT_DIR=samples/ OUTPUT_DIR=encrypted_binaries/

# Preview what would be processed
make batch-crypt INPUT_DIR=samples/ --dry-run

# Custom output directory
make batch-crypt INPUT_DIR=my_binaries/ OUTPUT_DIR=encrypted_output/

# Process with verbose logging
make batch-crypt INPUT_DIR=samples/ LOG_LEVEL=DEBUG
```

### **Rust-Crypter Workflow**

The Rust-Crypter integration follows a two-stage process:

1. **Stage 1: PE Obfuscation**
   - Applies standard PE obfuscation techniques
   - Mimicry, string obfuscation, import manipulation
   - Section padding, code encryption, static evasion
   - **Note**: Packing and compression are automatically disabled

2. **Stage 2: Advanced Encryption**
   - Encrypts the obfuscated PE using Rust-Crypter
   - Generates a decryption stub with embedded payload
   - Creates executable with in-memory decryption capabilities
   - Includes anti-VM detection features

### **Rust-Crypter Features**

- **In-Memory Execution**: Payload never written to disk in decrypted form
- **Anti-VM Detection**: Built-in virtual machine detection
- **Architecture Support**: Both x86 and x64 Windows targets
- **Automatic Compilation**: Handles Rust compilation and linking
- **Size Optimization**: Efficient stub generation
- **Batch Processing**: Full support for directory-based processing

### **Environment Variables**

- `RUST_CRYPTER_PATH` - Path to Rust-Crypter directory (set automatically by Makefile)
- `REDTEAM_MODE=true` - Required to enable toolkit
- `ALLOW_ACTIONS=true` - Required for file writes

## 🐳 Docker Deployment

The toolkit is containerized for easy deployment and consistent execution across different environments. Use the Makefile for simplified Docker operations.

### Quick Start with Makefile

```bash
# Build and run in one command
make docker-run INPUT=path/to/payload.exe

# Batch process a directory
make docker-run INPUT=samples/

# With custom output directory
make docker-run INPUT=samples/ OUTPUT_DIR=custom_output/

# With verbose logging
make docker-run INPUT=payload.exe LOG_LEVEL=DEBUG
```

### Docker Workflows

#### Single File Processing

```bash
# Using Makefile (recommended)
make docker-run INPUT=path/to/payload.exe

# Direct Docker command
docker run -v /host/input:/input -v /host/output:/output pe-evasion --input /input/payload.exe
```

#### Batch Directory Processing

```bash
# Using Makefile (recommended)
make docker-run INPUT=samples/

# Direct Docker command
docker run -v /host/samples:/input -v /host/output:/output pe-evasion --input /input
```

#### Advanced Usage

```bash
# Interactive mode (for debugging)
docker run -it -v /host/input:/input -v /host/output:/output pe-evasion bash

# Run with custom environment variables
docker run -e LOG_LEVEL=DEBUG -v /host/input:/input -v /host/output:/output pe-evasion --input /input

# Mount multiple directories
docker run -v /host/samples:/input -v /host/output:/output -v /host/config:/config pe-evasion --input /input
```

### Docker Features

- **Ubuntu 22.04 Base**: Stable, secure foundation
- **Automatic Detection**: Intelligently processes files or directories
- **Volume Mounting**: Easy input/output file management
- **Environment Variables**: Configurable logging and behavior
- **Help System**: Built-in usage instructions
- **Error Handling**: Graceful failure with informative messages
- **Batch Processing**: Full support for directory-based batch obfuscation

### Volume Mounting

The container uses volume mounts to access host files:

- **Input Volume**: Mount your input files/directories to `/input`
- **Output Volume**: Mount your desired output directory to `/output`
- **Internal Paths**: Use `/input` and `/output` paths inside the container

### Environment Variables

- `REDTEAM_MODE=true` (pre-set in container)
- `ALLOW_ACTIONS=true` (pre-set in container)
- `LOG_LEVEL` - Override logging level (DEBUG, INFO, WARNING, ERROR)

## 🔒 Safety & Compliance

- **ROE Compliance**: All operations require explicit environment variables
- **In-Memory Processing**: Decoding occurs in memory, not on disk
- **Audit Trail**: Comprehensive logging of all transformations
- **Fail-Safe**: Operations fail closed when safety checks fail
- **Research Tool**: Authorized lab use only
