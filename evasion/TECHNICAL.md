# Technical Overview

**High-level architecture and pipeline of the rt_evade PE Evasion Toolkit**

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
- **`packer.py`**: External packer integration (UPX), guarded and cleanup-safe
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
- **`rust_crypter.py`**: Rust-Crypter integration for advanced encryption and in-memory execution

## 🔄 PE Obfuscation Pipeline

### **1. Initial Analysis**

This stage involves a **PE Reader** that analyzes the input PE file. It parses and understands the file's structure, including headers, sections, and import tables.

### **2. Transformation Orchestration**

The **Transform Pipeline** acts as the central orchestrator, managing and applying various modules to the PE file to begin the obfuscation process.

### **3. Obfuscation Modules**

This is the core of the pipeline where multiple techniques are applied to change the file's characteristics.

| **Obfuscation Modules** | **Details** |
| --- | --- |
| **Mimicry Engine** | Alters file traits to mimic benign executables, such as section names and import tables.                |
| **String Obfuscation** | Identifies and conceals suspicious strings using techniques like Base64 encoding.                       |
| **Section Manipulation** | Modifies the file's layout by adding junk data, injecting payloads, or altering section traits.         |
| **Import Manipulation** | Inflates the import table with unnecessary entries or obfuscates API calls to confuse analysis.           |
---

### **4. Enhancement Modules**

| **Enhancement Modules** | **Details** |
| --- | --- |
| **Packer** | Utilizes the popular UPX packer but adds anti-analysis guards to prevent it from being easily unpacked by security tools. |
| **Compression** | Reduces file size and hinders static analysis by packing the code using algorithms like zlib or gzip.       |
| **Encryption** | Encrypts the file's content using methods like XOR encoding, requiring a key to decrypt at runtime.          |
| **Rust-Crypter Integration** | Advanced encryption using Rust-Crypter tool with in-memory execution stubs powered by memexec. **When enabled, disables packing and compression for optimal workflow.** |
| **Static Evasion** | Cleans up metadata and removes signatures that security tools might flag, such as compiler information.     |
| **Detection Mitigation** | Implements anti-analysis measures like monitoring file size changes, optimizing code sections, and generating benign timestamps. |

---

### **5. Finalization**

This stage involves reassembling and verifying the modified file.

* **PE Writer (Reassembly):** The obfuscated content is used to rebuild the PE file's structure.
* **PE Validator (Verification):** The newly created file is checked to ensure its integrity and that it remains executable.

### **6. Runtime Execution**

The final obfuscated PE file is ready for deployment. The choice of execution method can further enhance evasion.

| **Execution Method** | **Details** |
| --- | --- |
| **Dropper (Embedded)** | Embeds the PE file within another script (e.g., a Python module) that drops and executes it.              |
| **Standalone Executable** | Packages the entire application into a single binary, often with tools like PyInstaller, to avoid dependencies. |
| **In-Memory Decoding** | Decodes and executes the payload directly in memory without writing it to disk, a common stealth technique.      |
---

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

### Packing
- `packer.py` runs UPX under guardrails
- Enable via obfuscation config `packer_config.enable_packer=True`
- Optional args via env `UPX_ARGS` or config `packer_args`
- Requires `REDTEAM_MODE=true` and `ALLOW_ACTIONS=true`; uses temp files and cleans up

### Compression
- Algorithms: zlib, gzip, bz2; configurable levels
- Automatic decompression stub injection

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

### Rust-Crypter Integration
- Advanced PE encryption using Rust-Crypter tool
- In-memory execution stubs powered by memexec
- Anti-VM detection capabilities
- Support for x86 and x64 architectures
- Automatic stub compilation and deployment

## 📦 Batch Processing Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        BATCH PROCESSING PIPELINE                               │
└─────────────────────────────────────────────────────────────────────────────────┘

INPUT DIRECTORY
       │
       ▼
┌─────────────────┐
│  File Discovery │ ◄── Scan directory for binary files
│  (Auto-detect)  │     • Extension-based detection
│                 │     • Content-based analysis
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  File Queue     │ ◄── Queue all detected binary files
│  (Processing)   │
└─────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        PARALLEL PROCESSING                                      │
├─────────────────┬─────────────────┬─────────────────┬─────────────────────────┤
│   File 1        │   File 2        │   File 3        │   ... File N            │
│                 │                 │                 │                         │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────┐ │
│ │ PE Reader   │ │ │ PE Reader   │ │ │ PE Reader   │ │ │ PE Reader           │ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────┘ │ └─────────────────────┘ │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────┐ │
│ │ Obfuscation │ │ │ Obfuscation │ │ │ Obfuscation │ │ │ Obfuscation         │ │
│ │ Pipeline    │ │ │ Pipeline    │ │ │ Pipeline    │ │ │ Pipeline            │ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────┘ │ └─────────────────────┘ │
│ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────┐ │ ┌─────────────────────┐ │
│ │ PE Writer   │ │ │ PE Writer   │ │ │ PE Writer   │ │ │ PE Writer           │ │
│ └─────────────┘ │ └─────────────┘ │ └─────────────┘ │ └─────────────────────┘ │
└─────────────────┴─────────────────┴─────────────────┴─────────────────────────┘
       │
       ▼
┌─────────────────┐
│  Results        │ ◄── Collect success/failure statistics
│  Aggregation    │
└─────────────────┘
       │
       ▼
OUTPUT DIRECTORY (All obfuscated files)
```

## 🔒 Safety & Compliance Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        SAFETY & COMPLIANCE LAYER                               │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐
│  ROE Guards     │ ◄── Check REDTEAM_MODE environment variable
│  (Entry Point)  │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Action Guards  │ ◄── Check ALLOW_ACTIONS for file operations
│  (File I/O)     │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Memory-Only    │ ◄── Ensure decoding happens in memory
│  Processing     │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Audit Trail    │ ◄── Log all transformations and operations
│  (Logging)      │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Cleanup        │ ◄── Remove temporary artifacts and sensitive data
│  (Exit)         │
└─────────────────┘
```

## 📁 Project Structure

```
rt_evade/
├── core/                    # Core safety and orchestration
│   ├── guards.py           # ROE compliance and safety checks
│   ├── pipeline.py         # Transformation orchestration
│   └── transform.py        # Transform plan data structures
├── pe/                      # PE-specific modules
│   ├── compression.py       # Compression module
│   ├── encryption.py        # Encryption module
│   ├── string_obfuscation.py # String obfuscation
│   ├── section_manipulation.py # Section manipulation
│   ├── mimicry.py          # Mimicry engine
│   ├── obfuscator.py       # Main orchestrator
│   ├── reader.py           # PE file parsing
│   ├── writer.py           # PE file modification
│   └── validator.py        # PE format validation
├── dropper/                 # Runtime execution
│   ├── embed.py            # Embed PE into Python module
│   └── standalone.py       # Runtime decode helpers
├── batch_obfuscate.py       # Batch processing script
└── tests/                   # Comprehensive test suite
    ├── test_pe_compression.py
    ├── test_pe_encryption.py
    ├── test_pe_string_obfuscation.py
    ├── test_pe_section_manipulation.py
    └── ...
```

## 🔧 Rust-Crypter Integration Workflow

The Rust-Crypter integration provides advanced PE encryption and in-memory execution capabilities:

### **Setup Process**
1. **Rust Installation**: Ensure Rust toolchain is installed
2. **Target Installation**: Install Windows targets (x86_64-pc-windows-gnu, i686-pc-windows-gnu)
3. **Rust-Crypter Setup**: Clone and configure Rust-Crypter repository
4. **Environment Configuration**: Set RUST_CRYPTER_PATH environment variable

### **Encryption Workflow**
```
Input PE File
       │
       ▼
┌─────────────────┐
│  PE Validation  │ ◄── Check file size, format, architecture
│  (Size/Format)  │
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Rust-Crypter   │ ◄── Encrypt PE using Rust-Crypter
│  Encryption     │     • Generate encrypted_bytes.bin
│                 │     • Generate key.txt
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Stub Generation│ ◄── Create decryption stub
│  (Rust Compile) │     • Embed encrypted payload
│                 │     • Add memexec runtime
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Final Stub     │ ◄── Compiled executable
│  (Executable)   │     • In-memory decryption
│                 │     • Anti-VM features
└─────────────────┘
```

### **Key Features**
- **In-Memory Execution**: Payload never written to disk in decrypted form
- **Anti-VM Detection**: Built-in virtual machine detection
- **Architecture Support**: Both x86 and x64 Windows targets
- **Automatic Compilation**: Handles Rust compilation and linking
- **Size Optimization**: Efficient stub generation

### **Usage Examples**
```bash
# Basic usage
python -m rt_evade rust-crypter samples/out.bin

# With custom output and configuration
python -m rt_evade rust-crypter samples/out.bin \
    --output encrypted_payload.exe \
    --target-arch x86_64-pc-windows-gnu \
    --build-mode release

# With custom Rust-Crypter path
python -m rt_evade rust-crypter samples/out.bin \
    --rust-crypter-path /path/to/Rust-Crypter
```

## 🔄 Rust-Crypter Pipeline Integration

The Rust-Crypter integration is seamlessly integrated into the main transform pipeline, providing a two-stage workflow:

### **Stage 1: PE Obfuscation**
When `--pe-rust-crypter` is enabled, the pipeline applies standard PE obfuscation techniques:
- **Mimicry**: Template matching and characteristic copying
- **String Obfuscation**: Base64 encoding of suspicious strings
- **Import Manipulation**: Fake imports and dead code injection
- **Section Padding**: Junk data and entropy increase
- **Code Encryption**: XOR encryption of code sections
- **Static Evasion**: Metadata cleaning and signature removal
- **Detection Mitigation**: File size monitoring and timestamp optimization

**Note**: Packing and compression are automatically disabled when Rust-Crypter is enabled to ensure optimal workflow.

### **Stage 2: Rust-Crypter Encryption**
After obfuscation, the pipeline applies advanced encryption:
- **PE File Encryption**: Uses Rust-Crypter to encrypt the obfuscated PE
- **Stub Generation**: Creates a decryption stub with embedded payload
- **In-Memory Execution**: Stub uses memexec for runtime decryption
- **Anti-VM Features**: Built-in virtual machine detection
- **Architecture Support**: Both x86 and x64 Windows targets

### **Pipeline Workflow Diagram**
```
Input PE File
       │
       ▼
┌─────────────────┐
│  PE Obfuscation │ ◄── Stage 1: Standard obfuscation
│  (No Packing/   │     • Mimicry, strings, imports
│   Compression)  │     • Section padding, encryption
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Rust-Crypter   │ ◄── Stage 2: Advanced encryption
│  Encryption     │     • Encrypt obfuscated PE
│  + Stub Gen     │     • Generate in-memory stub
└─────────────────┘
       │
       ▼
┌─────────────────┐
│  Final Stub     │ ◄── Executable with embedded payload
│  (Executable)   │     • In-memory decryption
│                 │     • Anti-VM features
└─────────────────┘
```

### **Batch Processing Support**
The Rust-Crypter integration supports batch processing for multiple files:

```bash
# Batch obfuscation with Rust-Crypter
make batch-crypt INPUT_DIR=samples/

# Preview batch processing
make batch-crypt INPUT_DIR=samples/ --dry-run

# Custom output directory
make batch-crypt INPUT_DIR=samples/ OUTPUT_DIR=encrypted_binaries/
```

**Batch Processing Features:**
- **Automatic File Detection**: Finds all binary files in input directory
- **Preserved Filenames**: `samples/1` → `out/1`, `samples/payload.exe` → `out/payload.exe`
- **Parallel Processing**: Each file processed independently
- **Error Handling**: Continues processing even if individual files fail
- **Comprehensive Logging**: Detailed success/failure reporting

## 🎯 Key Design Principles

### 1. **Modularity**
- Each obfuscation technique is isolated in its own module
- Clear separation of concerns between reading, processing, and writing
- Easy to add new obfuscation techniques

### 2. **Safety First**
- All operations require explicit environment variable consent
- In-memory processing to avoid disk artifacts
- Comprehensive audit logging

### 3. **PE Format Integrity**
- Preserves PE structure while obfuscating content
- Validates output to ensure execution compatibility
- Maintains Windows PE format standards

### 4. **Research Focus**
- Designed for static ML evasion research
- Configurable obfuscation levels
- Detailed transformation logging for analysis

### 5. **Cross-Platform**
- Works on Windows, Linux, and macOS
- Uses Python standard library where possible
- Docker containerization for consistent execution
