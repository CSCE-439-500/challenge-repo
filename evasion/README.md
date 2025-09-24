# rt_evade (PE Evasion Toolkit)

**Modular PE static-ML evasion toolkit** with specialized components for comprehensive binary obfuscation. PE-in, PE-out with multi-layer obfuscation techniques.

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
make run-pe INPUT=path/to/payload.exe OUTPUT=out/obfuscated.exe

# One-shot: embed + bundle to standalone dropper
make single INPUT=path/to/payload.exe DECODE_KEY=mykey

# Batch obfuscation: process all binaries in a folder
make batch-obfuscate INPUT_DIR=samples/ OUTPUT_DIR=out/
make batch-dry-run INPUT_DIR=samples/  # Preview what would be processed

# Test individual modules
make test-compression
make test-encryption
make test-strings
make test-sections
```

### Docker Usage

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

## 🏗️ Modular Architecture

The toolkit has been refactored into specialized, focused modules for better maintainability and testing:

### Core Modules (`rt_evade.core`)
- **Guards**: Safety and ROE compliance enforcement
- **Transform Plans**: Data classes for obfuscation planning
- **Pipeline**: Orchestration of transformation workflows

### PE Modules (`rt_evade.pe`)
- **`reader.py`**: PE file parsing and analysis
- **`writer.py`**: PE file modification while preserving structure
- **`validator.py`**: PE format validation and integrity checking
- **`mimicry.py`**: Benign software template matching and characteristic copying
- **`obfuscator.py`**: Main orchestration engine (refactored)

### Specialized Obfuscation Modules
- **`compression.py`**: PE file compression with multiple algorithms (zlib, gzip, bz2)
- **`encryption.py`**: Code section encryption (XOR, simple substitution)
- **`string_obfuscation.py`**: Suspicious string identification and obfuscation
- **`section_manipulation.py`**: Section padding and entropy increase
- **`import_manipulator.py`**: Import table inflation and dead code injection
- **`static_evasion.py`**: Metadata cleaning and tool signature removal
- **`detection_mitigation.py`**: File size monitoring and timestamp preservation

### Dropper Modules (`rt_evade.dropper`)
- **`embed.py`**: Embed obfuscated PE into Python module
- **`standalone.py`**: Runtime decode helpers for in-memory reversal

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
- ✅ **134 tests passing**
- ✅ **Modular test structure** with focused test files
- ✅ **Integration tests** for end-to-end workflows
- ✅ **Unit tests** for each specialized module
- ✅ **Configuration validation** for all modules

## 📋 Available Makefile Targets

### Main Obfuscation Targets
- `make run` - Basic PE obfuscation (mimicry + strings + imports)
- `make run-pe` - Full PE obfuscation (all modules enabled)
- `make dry-run` - Show obfuscation plan without file writes
- `make single` - One-shot: embed + bundle to standalone dropper
- `make batch-obfuscate` - Obfuscate all binaries in a folder
- `make batch-dry-run` - Show what would be obfuscated without doing it

### Specialized Module Testing
- `make test-modules` - Test all specialized modules
- `make test-compression` - Test compression module only
- `make test-encryption` - Test encryption module only
- `make test-strings` - Test string obfuscation module only
- `make test-sections` - Test section manipulation module only

### Utility Targets
- `make test` - Run all tests (134 tests)
- `make dropper` - Execute obfuscated PE via dropper
- `make embed` - Embed PE into Python module
- `make bundle` - Create standalone executable
- `make clean` - Remove all build artifacts

## 🔧 Configuration

### Environment Variables
- `REDTEAM_MODE=true` - Required to enable toolkit
- `ALLOW_ACTIONS=true` - Required for file writes
- `DECODE_KEY=secret` - Encryption key for runtime decoding
- `LOG_LEVEL=INFO` - Logging verbosity

### Makefile Variables
- `INPUT` - Path to input PE file (default: `samples/sample.bin`)
- `INPUT_DIR` - Directory containing binaries to obfuscate (default: `samples`)
- `OUTPUT` - Output path (default: `out/out.bin`)
- `OUTPUT_DIR` - Output directory for batch obfuscation (default: `out`)
- `DECODE_KEY` - Encryption key (default: `secret`)
- `LOG_LEVEL` - Log level (default: `INFO`)

## 🛡️ PE Obfuscation Features

### Mimicry Engine
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

### Compression
- Multiple algorithms: zlib, gzip, bz2
- Configurable compression levels
- Automatic decompression stubs

### Encryption
- Code section encryption (XOR, simple substitution)
- Environment variable key support
- Runtime decryption capabilities

### Import Manipulation
- Import table inflation with benign APIs
- Dead code injection for feature dilution
- Suspicious API obfuscation

### Static Evasion
- Metadata cleaning and tool signature removal
- Suspicious string removal
- Timestamp normalization

### Detection Mitigation
- File size monitoring and optimization
- Section name optimization
- Benign timestamp generation

### Batch Processing
- **Automatic Binary Detection**: Identifies binary files by extension and content analysis
- **Same Filename Output**: Files named `1`, `2`, `3` etc. are output as `out/1`, `out/2`, `out/3`
- **Full PE Obfuscation**: All obfuscation modules enabled (mimicry, strings, imports, padding, compression, encryption)
- **Comprehensive Logging**: Detailed progress and success/failure reporting
- **Error Handling**: Continues processing even if individual files fail
- **Dry Run Support**: Preview functionality to see what would be processed

## 🔒 Safety & Compliance

- **ROE Compliance**: All operations require explicit environment variables
- **In-Memory Processing**: Decoding occurs in memory, not on disk
- **Audit Trail**: Comprehensive logging of all transformations
- **Fail-Safe**: Operations fail closed when safety checks fail
- **Research Tool**: Authorized lab use only

## 📁 Project Structure

```
rt_evade/
├── core/                    # Core safety and orchestration
├── pe/                      # PE-specific modules
│   ├── compression.py       # Compression module
│   ├── encryption.py        # Encryption module
│   ├── string_obfuscation.py # String obfuscation
│   ├── section_manipulation.py # Section manipulation
│   ├── mimicry.py          # Mimicry engine
│   ├── obfuscator.py       # Main orchestrator
│   └── ...                 # Other PE modules
├── dropper/                 # Runtime execution
├── batch_obfuscate.py       # Batch processing script
└── tests/                   # Comprehensive test suite
    ├── test_pe_compression.py
    ├── test_pe_encryption.py
    ├── test_pe_string_obfuscation.py
    ├── test_pe_section_manipulation.py
    └── ...
```

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

## 🐳 Docker Deployment

The toolkit is containerized for easy deployment and consistent execution across different environments.

### Building the Image

```bash
# Build the Docker image
docker build -t pe-evasion .

# Build with custom tag
docker build -t my-org/pe-evasion:latest .
```

### Running the Container

#### Single File Processing

```bash
# Process a single PE file
docker run -v /host/input:/input -v /host/output:/output pe-evasion --input /input/payload.exe

# With custom output directory
docker run -v /host/input:/input -v /host/output:/output pe-evasion \
    --input /input/payload.exe --output-dir /output/obfuscated
```

#### Batch Directory Processing

```bash
# Process all binaries in a directory
docker run -v /host/samples:/input -v /host/output:/output pe-evasion --input /input

# With verbose logging
docker run -v /host/samples:/input -v /host/output:/output pe-evasion \
    --input /input --log-level DEBUG
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

### Volume Mounting

The container uses volume mounts to access host files:

- **Input Volume**: Mount your input files/directories to `/input`
- **Output Volume**: Mount your desired output directory to `/output`
- **Internal Paths**: Use `/input` and `/output` paths inside the container

### Environment Variables

- `REDTEAM_MODE=true` (pre-set in container)
- `ALLOW_ACTIONS=true` (pre-set in container)
- `LOG_LEVEL` - Override logging level (DEBUG, INFO, WARNING, ERROR)
