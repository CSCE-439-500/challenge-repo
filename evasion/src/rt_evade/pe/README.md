# PE Obfuscation Module Structure

This directory contains the refactored PE obfuscation modules, organized into focused, manageable components.

## Module Overview

### Core Modules

- **`obfuscator.py`** - Main PE obfuscator that orchestrates all obfuscation techniques
- **`reader.py`** - PE file reading and parsing functionality
- **`writer.py`** - PE file writing and modification functionality
- **`validator.py`** - PE file validation and integrity checking

### Specialized Obfuscation Modules

- **`compression.py`** - PE file compression functionality
  - `PECompressor` class
  - `CompressionConfig` configuration
  - Supports zlib, gzip, and bz2 compression algorithms

- **`encryption.py`** - PE code section encryption functionality
  - `PEEncryptor` class
  - `EncryptionConfig` configuration
  - Supports XOR and simple encryption algorithms

- **`string_obfuscation.py`** - PE string obfuscation functionality
  - `PEStringObfuscator` class
  - `StringObfuscationConfig` configuration
  - Supports Base64, XOR, and simple substitution obfuscation

- **`section_manipulation.py`** - PE section padding and entropy modification
  - `PESectionManipulator` class
  - `SectionManipulationConfig` configuration
  - Handles section padding and entropy increase

### Supporting Modules

- **`mimicry.py`** - PE mimicry to make files look like benign software
- **`import_manipulator.py`** - Import table manipulation and dead code injection
- **`static_evasion.py`** - Static analysis evasion techniques
- **`detection_mitigation.py`** - Detection vector mitigation

## Configuration

The main `PEObfuscationConfig` class now supports sub-configurations for specialized modules:

```python
from rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig
from rt_evade.pe.compression import CompressionConfig
from rt_evade.pe.encryption import EncryptionConfig
from rt_evade.pe.string_obfuscation import StringObfuscationConfig
from rt_evade.pe.section_manipulation import SectionManipulationConfig

# Create specialized configurations
compression_config = CompressionConfig(
    enable_compression=True,
    compression_algorithm="zlib",
    compression_level=6
)

encryption_config = EncryptionConfig(
    enable_code_encryption=True,
    encryption_algorithm="xor",
    encryption_key_size=32
)

# Create main configuration with sub-configurations
config = PEObfuscationConfig(
    enable_compression=True,
    enable_code_encryption=True,
    compression_config=compression_config,
    encryption_config=encryption_config
)

# Initialize obfuscator
obfuscator = PEObfuscator(config)
```

## Usage

### Basic Usage

```python
from rt_evade.pe.obfuscator import PEObfuscator

# Initialize with default configuration
obfuscator = PEObfuscator()

# Obfuscate PE file
with open("malware.exe", "rb") as f:
    pe_data = f.read()

obfuscated_data = obfuscator.obfuscate_pe(pe_data)

# Save obfuscated file
with open("obfuscated_malware.exe", "wb") as f:
    f.write(obfuscated_data)
```

### Advanced Usage with Custom Configuration

```python
from rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig
from rt_evade.pe.compression import CompressionConfig
from rt_evade.pe.encryption import EncryptionConfig

# Create custom configuration
config = PEObfuscationConfig(
    enable_mimicry=True,
    enable_string_obfuscation=True,
    enable_compression=True,
    enable_code_encryption=True,
    compression_config=CompressionConfig(
        enable_compression=True,
        compression_algorithm="gzip",
        compression_level=9
    ),
    encryption_config=EncryptionConfig(
        enable_code_encryption=True,
        encryption_algorithm="simple",
        encryption_key_size=16
    )
)

obfuscator = PEObfuscator(config)
obfuscated_data = obfuscator.obfuscate_pe(pe_data)
```

## Testing

Each module has its own focused test file:

- `test_pe_compression.py` - Tests for compression functionality
- `test_pe_encryption.py` - Tests for encryption functionality
- `test_pe_string_obfuscation.py` - Tests for string obfuscation
- `test_pe_section_manipulation.py` - Tests for section manipulation
- `test_pe_obfuscator_refactored.py` - Integration tests for the main obfuscator

Run tests with:

```bash
# Run all PE tests
pytest tests/test_pe_*.py

# Run specific module tests
pytest tests/test_pe_compression.py
pytest tests/test_pe_encryption.py
```

## Benefits of Refactoring

1. **Modularity**: Each obfuscation technique is in its own focused module
2. **Maintainability**: Easier to modify and extend individual components
3. **Testability**: Each module can be tested independently
4. **Reusability**: Specialized modules can be used independently
5. **Configuration**: Fine-grained control over each obfuscation technique
6. **Readability**: Smaller, more focused files are easier to understand

## Migration from Original Code

The refactored code maintains backward compatibility with the original `PEObfuscator` interface. Existing code using the original obfuscator should continue to work without changes.

The main differences are:

1. **Sub-configurations**: New configuration options for specialized modules
2. **Modular structure**: Obfuscation techniques are now in separate modules
3. **Enhanced reporting**: More detailed reports from specialized modules
4. **Better error handling**: More specific error handling in each module
