"""Rust-Crypter integration module for advanced PE encryption and in-memory execution.

This module integrates the Rust-Crypter tool for encrypting PE files and generating
stubs that decrypt and execute them in memory using memexec.
"""
import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from ..core.guards import require_redteam_mode, guard_can_write

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RustCrypterConfig:
    """Configuration for Rust-Crypter integration."""
    
    enable_rust_crypter: bool = True
    rust_crypter_path: Optional[str] = None  # Path to Rust-Crypter directory
    target_architecture: str = "x86_64-pc-windows-gnu"  # Rust target
    build_mode: str = "release"  # release or debug
    anti_vm: bool = True  # Enable anti-VM features
    max_file_size: int = 5 * 1024 * 1024  # 5MB max file size


class RustCrypterIntegration:
    """Integration class for Rust-Crypter encryption and stub generation.
    
    This class provides functionality to:
    1. Encrypt PE files using Rust-Crypter
    2. Generate decryption stubs
    3. Compile stubs to standalone executables
    4. Handle in-memory execution
    """
    
    def __init__(self, config: Optional[RustCrypterConfig] = None):
        """Initialize Rust-Crypter integration.
        
        Args:
            config: Configuration options for Rust-Crypter
        """
        require_redteam_mode()
        
        self.config = config or RustCrypterConfig()
        self._validate_rust_crypter_setup()
        
        logger.info("action=rust_crypter_initialized config=%s", self.config)
    
    def _validate_rust_crypter_setup(self) -> None:
        """Validate that Rust-Crypter is properly set up.
        
        Raises:
            RuntimeError: If Rust-Crypter setup is invalid
        """
        # Check if Rust-Crypter path is provided
        if not self.config.rust_crypter_path:
            # Try to find Rust-Crypter in common locations
            possible_paths = [
                Path.cwd() / "rust-crypter",
                Path.cwd() / "Rust-Crypter",
                Path.home() / "rust-crypter",
                Path.home() / "Rust-Crypter",
            ]
            
            for path in possible_paths:
                if path.exists() and (path / "crypt" / "Cargo.toml").exists():
                    self.config = RustCrypterConfig(
                        **{**self.config.__dict__, "rust_crypter_path": str(path)}
                    )
                    break
            else:
                raise RuntimeError(
                    "Rust-Crypter not found. Please set RUST_CRYPTER_PATH environment variable "
                    "or ensure Rust-Crypter is in the current directory."
                )
        
        rust_crypter_path = Path(self.config.rust_crypter_path)
        
        # Validate Rust-Crypter structure
        required_files = [
            "crypt/Cargo.toml",
            "stub/Cargo.toml",
            "crypt/src/main.rs",
            "stub/src/main.rs",
        ]
        
        for file_path in required_files:
            if not (rust_crypter_path / file_path).exists():
                raise RuntimeError(
                    f"Invalid Rust-Crypter structure: missing {file_path}"
                )
        
        # Check if Rust toolchain is available
        try:
            subprocess.run(
                ["cargo", "--version"], 
                check=True, 
                capture_output=True, 
                text=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("Rust toolchain not found. Please install Rust.")
        
        logger.info("action=rust_crypter_validated path=%s", rust_crypter_path)
    
    def encrypt_pe_file(self, pe_data: bytes, output_dir: Optional[Path] = None) -> Tuple[bytes, bytes, str]:
        """Encrypt a PE file using Rust-Crypter.
        
        Args:
            pe_data: Raw PE file bytes to encrypt
            output_dir: Directory to write encrypted files (uses temp if None)
            
        Returns:
            Tuple of (encrypted_bytes, key_bytes, pe_filename)
            
        Raises:
            ValueError: If file is too large or encryption fails
        """
        if len(pe_data) > self.config.max_file_size:
            raise ValueError(
                f"File too large: {len(pe_data)} bytes > {self.config.max_file_size} bytes"
            )
        
        # Create temporary directory for encryption process
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Write PE file to temp location
            pe_filename = "target.exe"
            pe_path = temp_path / pe_filename
            pe_path.write_bytes(pe_data)
            
            # Copy PE file to Rust-Crypter crypt directory
            rust_crypter_path = Path(self.config.rust_crypter_path)
            crypt_input_path = rust_crypter_path / "crypt" / pe_filename
            
            # Remove existing file if it exists
            if crypt_input_path.exists():
                crypt_input_path.unlink()
            
            # Copy our PE file
            shutil.copy2(pe_path, crypt_input_path)
            
            # Run Rust-Crypter encryption
            try:
                result = subprocess.run(
                    ["cargo", "run", pe_filename],
                    cwd=rust_crypter_path / "crypt",
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                logger.info("action=rust_crypter_encrypt_success output=%s", result.stdout)
                
            except subprocess.CalledProcessError as e:
                logger.error("action=rust_crypter_encrypt_failed error=%s stderr=%s", e, e.stderr)
                raise ValueError(f"Rust-Crypter encryption failed: {e.stderr}")
            except subprocess.TimeoutExpired:
                raise ValueError("Rust-Crypter encryption timed out")
            
            # Read encrypted files
            encrypted_bytes_path = rust_crypter_path / "crypt" / "encrypted_bytes.bin"
            key_path = rust_crypter_path / "crypt" / "key.txt"
            
            if not encrypted_bytes_path.exists() or not key_path.exists():
                raise ValueError("Rust-Crypter did not generate expected output files")
            
            encrypted_bytes = encrypted_bytes_path.read_bytes()
            key_bytes = key_path.read_bytes()
            
            # Clean up generated files
            for file_path in [encrypted_bytes_path, key_path, crypt_input_path]:
                if file_path.exists():
                    file_path.unlink()
            
            # Copy to output directory if specified
            if output_dir:
                guard_can_write()
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "encrypted_bytes.bin").write_bytes(encrypted_bytes)
                (output_dir / "key.txt").write_bytes(key_bytes)
            
            logger.info(
                "action=pe_encrypted size=%d key_size=%d",
                len(encrypted_bytes),
                len(key_bytes)
            )
            
            return encrypted_bytes, key_bytes, pe_filename
    
    def generate_stub(self, encrypted_bytes: bytes, key_bytes: bytes, output_path: Optional[Path] = None) -> Path:
        """Generate and compile a decryption stub.
        
        Args:
            encrypted_bytes: Encrypted PE data
            key_bytes: Decryption key
            output_path: Where to write the compiled stub (uses temp if None)
            
        Returns:
            Path to the compiled stub executable
            
        Raises:
            ValueError: If stub generation fails
        """
        rust_crypter_path = Path(self.config.rust_crypter_path)
        stub_src_path = rust_crypter_path / "stub" / "src"
        
        # Write encrypted data and key to stub source directory
        (stub_src_path / "encrypted_bytes.bin").write_bytes(encrypted_bytes)
        (stub_src_path / "key.txt").write_bytes(key_bytes)
        
        # Compile the stub
        build_args = [
            "cargo", "build",
            f"--target={self.config.target_architecture}",
        ]
        
        if self.config.build_mode == "release":
            build_args.append("--release")
        
        try:
            result = subprocess.run(
                build_args,
                cwd=rust_crypter_path / "stub",
                check=True,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            logger.info("action=rust_crypter_stub_compiled output=%s", result.stdout)
            
        except subprocess.CalledProcessError as e:
            logger.error("action=rust_crypter_stub_failed error=%s stderr=%s", e, e.stderr)
            raise ValueError(f"Rust-Crypter stub compilation failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise ValueError("Rust-Crypter stub compilation timed out")
        
        # Determine output path
        if output_path is None:
            output_path = Path(tempfile.mktemp(suffix=".exe"))
        
        # Find the compiled stub
        build_dir = rust_crypter_path / "stub" / "target" / self.config.target_architecture
        if self.config.build_mode == "release":
            build_dir = build_dir / "release"
        else:
            build_dir = build_dir / "debug"
        
        stub_exe_path = build_dir / "stub.exe"
        
        if not stub_exe_path.exists():
            raise ValueError("Compiled stub not found at expected location")
        
        # Copy to final output location
        shutil.copy2(stub_exe_path, output_path)
        
        # Clean up generated files
        for file_path in [stub_src_path / "encrypted_bytes.bin", stub_src_path / "key.txt"]:
            if file_path.exists():
                file_path.unlink()
        
        logger.info("action=stub_generated path=%s size=%d", output_path, output_path.stat().st_size)
        
        return output_path
    
    def create_encrypted_payload(self, pe_data: bytes, output_path: Optional[Path] = None) -> Path:
        """Create a complete encrypted payload with stub.
        
        This is the main entry point that combines encryption and stub generation.
        
        Args:
            pe_data: Raw PE file bytes to encrypt
            output_path: Where to write the final stub executable
            
        Returns:
            Path to the compiled stub executable
        """
        # Step 1: Encrypt the PE file
        encrypted_bytes, key_bytes, pe_filename = self.encrypt_pe_file(pe_data)
        
        # Step 2: Generate and compile the stub
        stub_path = self.generate_stub(encrypted_bytes, key_bytes, output_path)
        
        logger.info(
            "action=encrypted_payload_created "
            "original_size=%d encrypted_size=%d stub_size=%d",
            len(pe_data),
            len(encrypted_bytes),
            stub_path.stat().st_size
        )
        
        return stub_path
    
    def get_encryption_report(self, original_data: bytes, encrypted_data: bytes, stub_path: Path) -> Dict[str, Any]:
        """Generate a report of the encryption and stub generation process.
        
        Args:
            original_data: Original PE file bytes
            encrypted_data: Encrypted PE data
            stub_path: Path to the generated stub
            
        Returns:
            Dictionary containing encryption report
        """
        return {
            "rust_crypter_enabled": self.config.enable_rust_crypter,
            "target_architecture": self.config.target_architecture,
            "build_mode": self.config.build_mode,
            "anti_vm_enabled": self.config.anti_vm,
            "original_size": len(original_data),
            "encrypted_size": len(encrypted_data),
            "stub_size": stub_path.stat().st_size,
            "total_size": len(encrypted_data) + stub_path.stat().st_size,
            "compression_ratio": (len(encrypted_data) / len(original_data)) * 100,
            "stub_hash": hashlib.sha256(stub_path.read_bytes()).hexdigest(),
        }


def create_rust_crypter_integration(config: Optional[RustCrypterConfig] = None) -> RustCrypterIntegration:
    """Factory function to create a Rust-Crypter integration instance.
    
    Args:
        config: Optional configuration for the integration
        
    Returns:
        Configured RustCrypterIntegration instance
    """
    return RustCrypterIntegration(config)
