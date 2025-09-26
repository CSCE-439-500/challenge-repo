"""Tests for Rust-Crypter integration module.

These tests verify the Rust-Crypter integration functionality.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from rt_evade.dropper.rust_crypter import RustCrypterIntegration, RustCrypterConfig


class TestRustCrypterConfig:
    """Test RustCrypterConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = RustCrypterConfig()
        
        assert config.enable_rust_crypter is True
        assert config.rust_crypter_path is None
        assert config.target_architecture == "x86_64-pc-windows-gnu"
        assert config.build_mode == "release"
        assert config.anti_vm is True
        assert config.max_file_size == 5 * 1024 * 1024
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = RustCrypterConfig(
            rust_crypter_path="/custom/path",
            target_architecture="i686-pc-windows-gnu",
            build_mode="debug",
            anti_vm=False,
            max_file_size=10 * 1024 * 1024,
        )
        
        assert config.rust_crypter_path == "/custom/path"
        assert config.target_architecture == "i686-pc-windows-gnu"
        assert config.build_mode == "debug"
        assert config.anti_vm is False
        assert config.max_file_size == 10 * 1024 * 1024


class TestRustCrypterIntegration:
    """Test RustCrypterIntegration class."""
    
    def setup_method(self):
        """Set up test environment."""
        os.environ["REDTEAM_MODE"] = "true"
        os.environ["ALLOW_ACTIONS"] = "true"
    
    def teardown_method(self):
        """Clean up test environment."""
        # Clean up environment variables if they were set
        if "REDTEAM_MODE" in os.environ:
            del os.environ["REDTEAM_MODE"]
        if "ALLOW_ACTIONS" in os.environ:
            del os.environ["ALLOW_ACTIONS"]
    
    @patch('rt_evade.dropper.rust_crypter.subprocess.run')
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    def test_validation_success(self, mock_exists, mock_run):
        """Test successful validation of Rust-Crypter setup."""
        # Mock file existence checks
        mock_exists.return_value = True
        
        # Mock cargo version check
        mock_run.return_value = MagicMock(stdout="cargo 1.70.0", returncode=0)
        
        config = RustCrypterConfig(rust_crypter_path="/test/path")
        
        # This should not raise an exception
        integration = RustCrypterIntegration(config)
        assert integration.config == config
    
    @patch('rt_evade.dropper.rust_crypter.subprocess.run')
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    def test_validation_rust_not_found(self, mock_exists, mock_run):
        """Test validation failure when Rust is not found."""
        # Mock file existence for Rust-Crypter structure
        mock_exists.return_value = True
        
        # Mock cargo not found
        mock_run.side_effect = FileNotFoundError("cargo not found")
        
        config = RustCrypterConfig(rust_crypter_path="/test/path")
        
        with pytest.raises(RuntimeError, match="Rust toolchain not found"):
            RustCrypterIntegration(config)
    
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    def test_validation_rust_crypter_not_found(self, mock_exists):
        """Test validation failure when Rust-Crypter is not found."""
        # Mock file not found
        mock_exists.return_value = False
        
        config = RustCrypterConfig(rust_crypter_path=None)
        
        with pytest.raises(RuntimeError, match="Rust-Crypter not found"):
            RustCrypterIntegration(config)
    
    @patch('rt_evade.dropper.rust_crypter.subprocess.run')
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    @patch('rt_evade.dropper.rust_crypter.shutil.copy2')
    @patch('rt_evade.dropper.rust_crypter.Path.write_bytes')
    @patch('rt_evade.dropper.rust_crypter.Path.read_bytes')
    @patch('rt_evade.dropper.rust_crypter.Path.unlink')
    def test_encrypt_pe_file_success(self, mock_unlink, mock_read_bytes, mock_write_bytes, 
                                   mock_copy2, mock_exists, mock_run):
        """Test successful PE file encryption."""
        # Mock file existence
        mock_exists.return_value = True
        
        # Mock cargo version check and encryption process
        mock_run.side_effect = [
            MagicMock(stdout="cargo 1.70.0", returncode=0),  # cargo version
            MagicMock(stdout="Encryption successful", returncode=0),  # cargo run
        ]
        
        # Mock file operations
        mock_read_bytes.side_effect = [
            b"encrypted_data",  # encrypted_bytes.bin
            b"encryption_key",  # key.txt
        ]
        
        # Mock unlink to avoid FileNotFoundError
        mock_unlink.return_value = None
        
        config = RustCrypterConfig(rust_crypter_path="/test/path")
        integration = RustCrypterIntegration(config)
        
        # Test encryption
        pe_data = b"test_pe_data"
        encrypted_bytes, key_bytes, filename = integration.encrypt_pe_file(pe_data)
        
        assert encrypted_bytes == b"encrypted_data"
        assert key_bytes == b"encryption_key"
        assert filename == "target.exe"
    
    def test_encrypt_pe_file_too_large(self):
        """Test encryption failure when file is too large."""
        config = RustCrypterConfig(max_file_size=100)  # 100 bytes limit
        
        with patch('rt_evade.dropper.rust_crypter.subprocess.run'):
            with patch('rt_evade.dropper.rust_crypter.Path.exists', return_value=True):
                integration = RustCrypterIntegration(config)
        
        # Test with large file
        large_pe_data = b"x" * 200  # 200 bytes
        
        with pytest.raises(ValueError, match="File too large"):
            integration.encrypt_pe_file(large_pe_data)
    
    @patch('rt_evade.dropper.rust_crypter.subprocess.run')
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    @patch('rt_evade.dropper.rust_crypter.shutil.copy2')
    @patch('rt_evade.dropper.rust_crypter.Path.write_bytes')
    @patch('rt_evade.dropper.rust_crypter.Path.read_bytes')
    @patch('rt_evade.dropper.rust_crypter.Path.unlink')
    @patch('rt_evade.dropper.rust_crypter.Path.stat')
    def test_generate_stub_success(self, mock_stat, mock_unlink, mock_read_bytes, mock_write_bytes,
                                 mock_copy2, mock_exists, mock_run):
        """Test successful stub generation."""
        # Mock file existence
        mock_exists.return_value = True
        
        # Mock cargo version check and stub compilation
        mock_run.side_effect = [
            MagicMock(stdout="cargo 1.70.0", returncode=0),  # cargo version
            MagicMock(stdout="Stub compiled successfully", returncode=0),  # cargo build
        ]
        
        # Mock file operations
        mock_read_bytes.return_value = b"stub_executable_data"
        mock_unlink.return_value = None
        
        # Mock stat for file size
        mock_stat.return_value = MagicMock(st_size=1024)
        
        config = RustCrypterConfig(rust_crypter_path="/test/path")
        integration = RustCrypterIntegration(config)
        
        # Test stub generation
        encrypted_bytes = b"encrypted_data"
        key_bytes = b"encryption_key"
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "stub.exe"
            stub_path = integration.generate_stub(encrypted_bytes, key_bytes, output_path)
            
            assert stub_path == output_path
    
    def test_get_encryption_report(self):
        """Test encryption report generation."""
        config = RustCrypterConfig()
        
        with patch('rt_evade.dropper.rust_crypter.subprocess.run'):
            with patch('rt_evade.dropper.rust_crypter.Path.exists', return_value=True):
                integration = RustCrypterIntegration(config)
        
        # Create mock stub file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"stub_data")
            temp_file.flush()
            stub_path = Path(temp_file.name)
        
        try:
            original_data = b"original_pe_data"
            encrypted_data = b"encrypted_data"
            
            report = integration.get_encryption_report(original_data, encrypted_data, stub_path)
            
            assert report["rust_crypter_enabled"] is True
            assert report["target_architecture"] == "x86_64-pc-windows-gnu"
            assert report["build_mode"] == "release"
            assert report["anti_vm_enabled"] is True
            assert report["original_size"] == len(original_data)
            assert report["encrypted_size"] == len(encrypted_data)
            assert report["stub_size"] == len(b"stub_data")
            assert "stub_hash" in report
        
        finally:
            # Clean up
            if stub_path.exists():
                stub_path.unlink()


class TestRustCrypterIntegrationEdgeCases:
    """Test edge cases and error conditions."""
    
    def setup_method(self):
        """Set up test environment."""
        os.environ["REDTEAM_MODE"] = "true"
        os.environ["ALLOW_ACTIONS"] = "true"
    
    def teardown_method(self):
        """Clean up test environment."""
        if "REDTEAM_MODE" in os.environ:
            del os.environ["REDTEAM_MODE"]
        if "ALLOW_ACTIONS" in os.environ:
            del os.environ["ALLOW_ACTIONS"]
    
    def test_redteam_mode_required(self):
        """Test that REDTEAM_MODE is required."""
        if "REDTEAM_MODE" in os.environ:
            del os.environ["REDTEAM_MODE"]
        
        with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
            RustCrypterIntegration()
    
    @patch('rt_evade.dropper.rust_crypter.subprocess.run')
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    @patch('rt_evade.dropper.rust_crypter.shutil.copy2')
    @patch('rt_evade.dropper.rust_crypter.Path.write_bytes')
    @patch('rt_evade.dropper.rust_crypter.Path.unlink')
    def test_encryption_timeout(self, mock_unlink, mock_write_bytes, mock_copy2, mock_exists, mock_run):
        """Test encryption timeout handling."""
        mock_exists.return_value = True
        mock_run.side_effect = [
            MagicMock(stdout="cargo 1.70.0", returncode=0),  # cargo version
            subprocess.TimeoutExpired("cargo", 300),  # encryption timeout
        ]
        mock_unlink.return_value = None
        
        config = RustCrypterConfig(rust_crypter_path="/test/path")
        integration = RustCrypterIntegration(config)
        
        with pytest.raises(ValueError, match="Rust-Crypter encryption timed out"):
            integration.encrypt_pe_file(b"test_data")
    
    @patch('rt_evade.dropper.rust_crypter.subprocess.run')
    @patch('rt_evade.dropper.rust_crypter.Path.exists')
    @patch('rt_evade.dropper.rust_crypter.shutil.copy2')
    @patch('rt_evade.dropper.rust_crypter.Path.write_bytes')
    @patch('rt_evade.dropper.rust_crypter.Path.unlink')
    def test_encryption_failure(self, mock_unlink, mock_write_bytes, mock_copy2, mock_exists, mock_run):
        """Test encryption failure handling."""
        # Mock file existence - return True for all files during validation
        mock_exists.return_value = True
        mock_run.side_effect = [
            MagicMock(stdout="cargo 1.70.0", returncode=0),  # cargo version
            subprocess.CalledProcessError(1, "cargo", stderr="Encryption failed"),  # encryption failure
        ]
        mock_unlink.return_value = None
        
        config = RustCrypterConfig(rust_crypter_path="/test/path")
        integration = RustCrypterIntegration(config)
        
        with pytest.raises(ValueError, match="Rust-Crypter encryption failed"):
            integration.encrypt_pe_file(b"test_data")
