# rt_evade (PE Evasion Toolkit)

**Modular PE static-ML evasion toolkit** with specialized components for comprehensive binary obfuscation. PE-in, PE-out with multi-layer obfuscation techniques.

[![License](https://img.shields.io/badge/license-Research%20Use%20Only-red.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-supported-2496ED.svg)](https://docker.com)

## 🎯 What is rt_evade?

rt_evade is a specialized toolkit designed for **static ML evasion research**. It takes PE (Portable Executable) files as input and applies multiple layers of obfuscation to make them appear benign to static analysis tools while preserving their original functionality.

### Key Features

- **🤖 Autonomous Agent**: AI-powered obfuscation agent with ML evasion testing
- **🔧 Modular Architecture**: Specialized components for different obfuscation techniques
- **🛡️ PE Format Integrity**: Preserves Windows PE structure while obfuscating content
- **🔒 Safety First**: ROE compliance with explicit environment variable controls
- **📦 Batch Processing**: Process entire directories of binaries automatically
- **🐳 Docker Support**: Containerized deployment for consistent execution
- **🧪 Comprehensive Testing**: 202 tests covering all modules and workflows

### Obfuscation Techniques

- **🤖 Autonomous Agent**: AI-powered iterative obfuscation with ML evasion testing
- **Mimicry**: Copy characteristics from benign software
- **String Obfuscation**: Hide suspicious strings using Base64 encoding
- **Section Manipulation**: Add junk data and modify section characteristics
- **Import Inflation**: Add benign APIs and dead code
- **Compression**: Multiple algorithms (zlib, gzip, bz2)
- **Encryption**: Code section encryption with environment key support
- **Static Evasion**: Clean metadata and remove tool signatures

## 🚀 Quick Start

```bash
# first
pip install -r requirements.txt

# Basic PE obfuscation
make run INPUT=path/to/payload.exe

# Full obfuscation with all modules
make run-pe INPUT=path/to/payload.exe

# Autonomous obfuscation agent with ML evasion testing
make agent INPUT=path/to/payload.exe

# Batch process a directory
make batch-obfuscate INPUT_DIR=samples/

# Docker deployment (no need to run pip install for this)
make docker-run INPUT=path/to/payload.exe
```

## 📚 Documentation

- **[USAGE.md](USAGE.md)** - Complete usage guide with all commands and examples
- **[TECHNICAL.md](TECHNICAL.md)** - Technical overview, architecture, and pipeline diagrams

## 🏗️ Architecture Overview

The toolkit uses a modular pipeline approach:

```
Input PE → Analysis → Obfuscation Pipeline → Validation → Output PE
                ↓
        [Mimicry, Strings, Sections, Imports, Compression, Encryption]
```

Each module is specialized and can be tested independently. The pipeline orchestrates multiple obfuscation techniques while maintaining PE format integrity.

## 🔒 Safety & Compliance

- **ROE Compliance**: All operations require `REDTEAM_MODE=true`
- **File Operations**: Require `ALLOW_ACTIONS=true` for writes
- **In-Memory Processing**: Decoding occurs in memory, not on disk
- **Audit Trail**: Comprehensive logging of all transformations
- **Research Tool**: Authorized lab use only

## 🧪 Testing

```bash
# Run all tests (202 tests)
make test

# Test individual modules
make test-modules
make test-compression
make test-encryption

# Test autonomous agent
make test-agent
```

## 🐳 Docker Support

The toolkit is fully containerized for easy deployment:

```bash
# Build and run
make docker-build
make docker-run INPUT=path/to/file

# Batch processing
make docker-run INPUT=samples/
```

## 📋 Requirements

- Python 3.10+
- Docker (optional, for containerized deployment)
- Windows PE files as input
- Environment variables for safety controls

## ⚠️ Important Notes

- **Research Tool**: This toolkit is designed for authorized red-team exercises and static ML evasion research
- **PE Files Only**: Input must be Windows Portable Executable files
- **Safety Controls**: All operations require explicit environment variable consent
- **No Malicious Use**: Intended for defensive research and authorized testing only

---

**For detailed usage instructions, see [USAGE.md](USAGE.md)**
**For technical details and architecture, see [TECHNICAL.md](TECHNICAL.md)**
