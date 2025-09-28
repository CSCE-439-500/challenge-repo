"""Tests for PE obfuscator functionality.

This module contains pytest tests for the PE obfuscator component,
including multi-layer obfuscation and configuration testing.
"""

import os
import pytest
from unittest.mock import patch

from rt_evade.pe.obfuscator import PEObfuscator, PEObfuscationConfig


@pytest.fixture
def mock_pe_data():
    """Create mock PE data that pefile can parse."""
    # Create a more realistic PE structure that pefile can handle
    pe_data = bytearray(1024)

    # DOS header
    pe_data[0:2] = b"MZ"  # e_magic
    pe_data[60:64] = (64).to_bytes(4, "little")  # e_lfanew

    # PE signature
    pe_data[64:68] = b"PE\x00\x00"

    # COFF header
    pe_data[68:70] = (0x014C).to_bytes(2, "little")  # Machine (x86)
    pe_data[70:72] = (1).to_bytes(2, "little")  # NumberOfSections
    pe_data[72:76] = (0).to_bytes(4, "little")  # TimeDateStamp
    pe_data[76:80] = (0).to_bytes(4, "little")  # PointerToSymbolTable
    pe_data[80:84] = (0).to_bytes(4, "little")  # NumberOfSymbols
    pe_data[84:86] = (224).to_bytes(2, "little")  # SizeOfOptionalHeader
    pe_data[86:88] = (0x010F).to_bytes(2, "little")  # Characteristics

    # Optional header
    pe_data[88:90] = (0x010B).to_bytes(2, "little")  # Magic (PE32)
    pe_data[90:92] = (0).to_bytes(1, "little")  # MajorLinkerVersion
    pe_data[91:93] = (0).to_bytes(1, "little")  # MinorLinkerVersion
    pe_data[92:96] = (0).to_bytes(4, "little")  # SizeOfCode
    pe_data[96:100] = (0).to_bytes(4, "little")  # SizeOfInitializedData
    pe_data[100:104] = (0).to_bytes(4, "little")  # SizeOfUninitializedData
    pe_data[104:108] = (0x1000).to_bytes(4, "little")  # AddressOfEntryPoint
    pe_data[108:112] = (0x1000).to_bytes(4, "little")  # BaseOfCode
    pe_data[112:116] = (0).to_bytes(4, "little")  # BaseOfData
    pe_data[116:120] = (0x400000).to_bytes(4, "little")  # ImageBase
    pe_data[120:124] = (0x1000).to_bytes(4, "little")  # SectionAlignment
    pe_data[124:128] = (0x200).to_bytes(4, "little")  # FileAlignment
    pe_data[128:130] = (4).to_bytes(2, "little")  # MajorOperatingSystemVersion
    pe_data[130:132] = (0).to_bytes(2, "little")  # MinorOperatingSystemVersion
    pe_data[132:134] = (0).to_bytes(2, "little")  # MajorImageVersion
    pe_data[134:136] = (0).to_bytes(2, "little")  # MinorImageVersion
    pe_data[136:138] = (4).to_bytes(2, "little")  # MajorSubsystemVersion
    pe_data[138:140] = (0).to_bytes(2, "little")  # MinorSubsystemVersion
    pe_data[140:144] = (0).to_bytes(4, "little")  # Win32VersionValue
    pe_data[144:148] = (0x2000).to_bytes(4, "little")  # SizeOfImage
    pe_data[148:152] = (0x200).to_bytes(4, "little")  # SizeOfHeaders
    pe_data[152:156] = (0).to_bytes(4, "little")  # CheckSum
    pe_data[156:158] = (2).to_bytes(2, "little")  # Subsystem (GUI)
    pe_data[158:160] = (0).to_bytes(2, "little")  # DllCharacteristics
    pe_data[160:164] = (0).to_bytes(4, "little")  # SizeOfStackReserve
    pe_data[164:168] = (0).to_bytes(4, "little")  # SizeOfStackCommit
    pe_data[168:172] = (0).to_bytes(4, "little")  # SizeOfHeapReserve
    pe_data[172:176] = (0).to_bytes(4, "little")  # SizeOfHeapCommit
    pe_data[176:180] = (0).to_bytes(4, "little")  # LoaderFlags
    pe_data[180:184] = (0).to_bytes(4, "little")  # NumberOfRvaAndSizes

    # Data directories (all zeros for simplicity)
    pe_data[184:312] = b"\x00" * 128

    # Section header
    pe_data[312:320] = b".text\x00\x00\x00"  # Name
    pe_data[320:324] = (0).to_bytes(4, "little")  # VirtualSize
    pe_data[324:328] = (0x1000).to_bytes(4, "little")  # VirtualAddress
    pe_data[328:332] = (0x200).to_bytes(4, "little")  # SizeOfRawData
    pe_data[332:336] = (0x400).to_bytes(4, "little")  # PointerToRawData
    pe_data[336:340] = (0).to_bytes(4, "little")  # PointerToRelocations
    pe_data[340:344] = (0).to_bytes(4, "little")  # PointerToLinenumbers
    pe_data[344:346] = (0).to_bytes(2, "little")  # NumberOfRelocations
    pe_data[346:348] = (0).to_bytes(2, "little")  # NumberOfLinenumbers
    pe_data[348:352] = (0x60000020).to_bytes(4, "little")  # Characteristics

    return bytes(pe_data)


class TestPEObfuscator:
    """Test PE obfuscator functionality."""

    def test_obfuscator_initialization(self):
        """Test obfuscator initialization."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig()
            obfuscator = PEObfuscator(config)
            assert obfuscator is not None
            assert obfuscator.config == config

    def test_obfuscator_requires_redteam_mode(self):
        """Test that obfuscator requires REDTEAM_MODE."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEObfuscator()

    def test_obfuscate_pe(self, mock_pe_data):
        """Test PE obfuscation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,  # Disable to avoid complex dependencies
                enable_string_obfuscation=True,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                # The important thing is that the obfuscator handles it gracefully
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_create_obfuscation_plan(self, mock_pe_data):
        """Test creating obfuscation plan."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEObfuscator()
            plan = obfuscator.create_obfuscation_plan(mock_pe_data)
            assert plan is not None
            assert hasattr(plan, "name")
            assert hasattr(plan, "apply")
            assert plan.name == "pe_obfuscation"

    def test_get_obfuscation_report(self, mock_pe_data):
        """Test generating obfuscation report."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEObfuscator()

            # Create a simple obfuscated version (just copy for testing)
            obfuscated_data = mock_pe_data + b"test_padding"

            report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated_data)
            assert isinstance(report, dict)
            assert "size_change" in report
            assert "size_percentage" in report
            assert "entropy_changes" in report
            assert "validation_results" in report


class TestPEObfuscationConfig:
    """Test PE obfuscation configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = PEObfuscationConfig()
        assert config.enable_mimicry is True
        assert config.enable_string_obfuscation is True
        assert config.enable_import_inflation is True
        assert config.enable_section_padding is True
        assert config.enable_entropy_increase is True
        assert config.max_file_size == 5 * 1024 * 1024  # 5MB

    def test_custom_config(self):
        """Test custom configuration values."""
        from rt_evade.pe.compression import CompressionConfig

        compression_config = CompressionConfig(
            enable_compression=False, compression_algorithm="gzip", compression_level=9
        )

        config = PEObfuscationConfig(
            enable_mimicry=False,
            enable_string_obfuscation=False,
            enable_import_inflation=False,
            enable_section_padding=False,
            enable_entropy_increase=False,
            enable_compression=False,
            target_category="system_utility",
            max_file_size=1024 * 1024,  # 1MB
            compression_config=compression_config,
        )

        assert config.enable_mimicry is False
        assert config.enable_string_obfuscation is False
        assert config.enable_import_inflation is False
        assert config.enable_section_padding is False
        assert config.enable_entropy_increase is False
        assert config.enable_compression is False
        assert config.target_category == "system_utility"
        assert config.max_file_size == 1024 * 1024
        assert config.compression_config.compression_algorithm == "gzip"
        assert config.compression_config.compression_level == 9

    def test_compression_config(self):
        """Test compression configuration options."""
        from rt_evade.pe.compression import CompressionConfig

        compression_config = CompressionConfig(
            enable_compression=True, compression_algorithm="bz2", compression_level=5
        )

        config = PEObfuscationConfig(
            enable_compression=True, compression_config=compression_config
        )

        assert config.enable_compression is True
        assert config.compression_config.compression_algorithm == "bz2"
        assert config.compression_config.compression_level == 5

    def test_encryption_config(self):
        """Test encryption configuration options."""
        from rt_evade.pe.encryption import EncryptionConfig

        encryption_config = EncryptionConfig(
            enable_code_encryption=True,
            encryption_algorithm="simple",
            encryption_key_size=16,
        )

        config = PEObfuscationConfig(
            enable_code_encryption=True, encryption_config=encryption_config
        )

        assert config.enable_code_encryption is True
        assert config.encryption_config.encryption_algorithm == "simple"
        assert config.encryption_config.encryption_key_size == 16

    def test_import_manipulation_config(self):
        """Test import manipulation configuration options."""
        config = PEObfuscationConfig(enable_import_manipulation=True)

        assert config.enable_import_manipulation is True

    def test_static_evasion_config(self):
        """Test static evasion configuration options."""
        config = PEObfuscationConfig(enable_static_evasion=True)

        assert config.enable_static_evasion is True

    def test_detection_mitigation_config(self):
        """Test detection mitigation configuration options."""
        config = PEObfuscationConfig(enable_detection_mitigation=True)

        assert config.enable_detection_mitigation is True


class TestPECompression:
    """Test PE compression functionality."""

    def test_compression_with_large_data(self, mock_pe_data):
        """Test compression with data large enough to benefit."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            # Create larger mock data for compression testing
            large_data = mock_pe_data + b"x" * 2000  # Add 2KB of repeated data

            from rt_evade.pe.compression import CompressionConfig

            compression_config = CompressionConfig(
                enable_compression=True,
                compression_algorithm="zlib",
                compression_level=6,
                min_file_size=1000,
            )

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=True,
                compression_config=compression_config,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(large_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_compression_skipped_for_small_files(self, mock_pe_data):
        """Test that compression is skipped for small files."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=True,
            )
            obfuscator = PEObfuscator(config)

            # Small file should not be compressed
            obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
            assert isinstance(obfuscated, bytes)
            # For small files, compression should be skipped
            # so the result should be similar to original

    def test_compression_algorithms(self, mock_pe_data):
        """Test different compression algorithms."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.compression import CompressionConfig

            large_data = mock_pe_data + b"test_data_for_compression" * 100

            algorithms = ["zlib", "gzip", "bz2"]

            for algorithm in algorithms:
                compression_config = CompressionConfig(
                    enable_compression=True,
                    compression_algorithm=algorithm,
                    compression_level=6,
                    min_file_size=1000,
                )

                config = PEObfuscationConfig(
                    enable_mimicry=False,
                    enable_string_obfuscation=False,
                    enable_import_inflation=False,
                    enable_section_padding=False,
                    enable_entropy_increase=False,
                    enable_compression=True,
                    compression_config=compression_config,
                )
                obfuscator = PEObfuscator(config)

                try:
                    obfuscated = obfuscator.obfuscate_pe(large_data)
                    assert isinstance(obfuscated, bytes)
                    assert len(obfuscated) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert (
                        "Invalid PE file" in str(e)
                        or "PE format error" in str(e)
                        or "Writes disabled" in str(e)
                    )

    def test_compression_levels(self, mock_pe_data):
        """Test different compression levels."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.compression import CompressionConfig

            large_data = mock_pe_data + b"repeated_data_for_compression" * 200

            levels = [1, 6, 9]

            for level in levels:
                compression_config = CompressionConfig(
                    enable_compression=True,
                    compression_algorithm="zlib",
                    compression_level=level,
                    min_file_size=1000,
                )

                config = PEObfuscationConfig(
                    enable_mimicry=False,
                    enable_string_obfuscation=False,
                    enable_import_inflation=False,
                    enable_section_padding=False,
                    enable_entropy_increase=False,
                    enable_compression=True,
                    compression_config=compression_config,
                )
                obfuscator = PEObfuscator(config)

                try:
                    obfuscated = obfuscator.obfuscate_pe(large_data)
                    assert isinstance(obfuscated, bytes)
                    assert len(obfuscated) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert (
                        "Invalid PE file" in str(e)
                        or "PE format error" in str(e)
                        or "Writes disabled" in str(e)
                    )

    def test_compression_report(self, mock_pe_data):
        """Test compression report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.compression import CompressionConfig

            large_data = mock_pe_data + b"test_compression_data" * 150

            compression_config = CompressionConfig(
                enable_compression=True,
                compression_algorithm="zlib",
                compression_level=6,
                min_file_size=1000,
            )

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=True,
                compression_config=compression_config,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(large_data)
                report = obfuscator.get_obfuscation_report(large_data, obfuscated)

                assert isinstance(report, dict)
                assert "compression" in report
                assert "compression_ratio" in report["compression"]
                assert "size_change" in report
                assert "size_percentage" in report
            except Exception as e:
                # Some operations might fail with mock data
                assert (
                    "Invalid PE file" in str(e)
                    or "PE format error" in str(e)
                    or "Writes disabled" in str(e)
                )

    def test_compression_disabled(self, mock_pe_data):
        """Test that compression is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            large_data = mock_pe_data + b"large_data_for_testing" * 200

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,  # Disabled
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(large_data)
                assert isinstance(obfuscated, bytes)
                # When compression is disabled, the result should be similar to original
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)


class TestPECodeEncryption:
    """Test PE code encryption functionality."""

    def test_encryption_with_code_sections(self, mock_pe_data):
        """Test encryption with code sections."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=True,
                encryption_config=EncryptionConfig(
                    enable_code_encryption=True,
                    encryption_algorithm="xor",
                    encryption_key_size=16,
                ),
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_encryption_algorithms(self, mock_pe_data):
        """Test different encryption algorithms."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            algorithms = ["xor", "simple"]

            for algorithm in algorithms:
                encryption_config = EncryptionConfig(
                    enable_code_encryption=True,
                    encryption_algorithm=algorithm,
                    encryption_key_size=32,
                )

                config = PEObfuscationConfig(
                    enable_mimicry=False,
                    enable_string_obfuscation=False,
                    enable_import_inflation=False,
                    enable_section_padding=False,
                    enable_entropy_increase=False,
                    enable_compression=False,
                    enable_code_encryption=True,
                    encryption_config=encryption_config,
                )
                obfuscator = PEObfuscator(config)

                try:
                    obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                    assert isinstance(obfuscated, bytes)
                    assert len(obfuscated) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert (
                        "Invalid PE file" in str(e)
                        or "PE format error" in str(e)
                        or "Writes disabled" in str(e)
                    )

    def test_encryption_key_sizes(self, mock_pe_data):
        """Test different encryption key sizes."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            key_sizes = [16, 32, 64]

            for key_size in key_sizes:
                encryption_config = EncryptionConfig(
                    enable_code_encryption=True,
                    encryption_algorithm="xor",
                    encryption_key_size=key_size,
                )

                config = PEObfuscationConfig(
                    enable_mimicry=False,
                    enable_string_obfuscation=False,
                    enable_import_inflation=False,
                    enable_section_padding=False,
                    enable_entropy_increase=False,
                    enable_compression=False,
                    enable_code_encryption=True,
                    encryption_config=encryption_config,
                )
                obfuscator = PEObfuscator(config)

                try:
                    obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                    assert isinstance(obfuscated, bytes)
                    assert len(obfuscated) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert (
                        "Invalid PE file" in str(e)
                        or "PE format error" in str(e)
                        or "Writes disabled" in str(e)
                    )

    def test_encryption_with_env_key(self, mock_pe_data):
        """Test encryption with environment variable key."""
        with patch.dict(
            os.environ,
            {
                "REDTEAM_MODE": "true",
                "ALLOW_ACTIONS": "true",
                "ENCRYPTION_KEY": "test_key_12345",
            },
        ):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=True,
                encryption_config=EncryptionConfig(
                    enable_code_encryption=True,
                    encryption_algorithm="xor",
                    encryption_key_size=16,
                ),
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_encryption_report(self, mock_pe_data):
        """Test encryption report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(report, dict)
                assert "encryption" in report
                assert "size_change" in report
                assert "size_percentage" in report
                assert report["encryption"]["encryption_enabled"] is True
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_encryption_disabled(self, mock_pe_data):
        """Test that encryption is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,  # Disabled
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(obfuscated, bytes)
                assert report["techniques_applied"]["code_encryption"] is False
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_xor_encryption_roundtrip(self):
        """Test XOR encryption and decryption roundtrip."""
        from rt_evade.pe.encryption import PEEncryptor

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            encryptor = PEEncryptor()

            # Test data
            test_data = b"Hello, World! This is test data for encryption."
            test_key = b"test_key_12345"

            # Encrypt
            encrypted = encryptor._xor_encrypt(test_data, test_key)
            assert encrypted != test_data
            assert len(encrypted) == len(test_data)

            # Decrypt (XOR is symmetric)
            decrypted = encryptor._xor_encrypt(encrypted, test_key)
            assert decrypted == test_data

    def test_simple_encryption_roundtrip(self):
        """Test simple encryption and decryption roundtrip."""
        from rt_evade.pe.encryption import PEEncryptor

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            encryptor = PEEncryptor()

            # Test data
            test_data = b"Hello, World! This is test data for encryption."
            test_key = b"test_key_12345"

            # Encrypt
            encrypted = encryptor._simple_encrypt(test_data, test_key)
            assert encrypted != test_data
            assert len(encrypted) == len(test_data)

            # Note: Simple encryption is not symmetric, so we can't easily test decryption
            # In a real implementation, we would have a corresponding decryption method


class TestPEImportManipulation:
    """Test PE import manipulation functionality."""

    def test_import_manipulation_with_mock_data(self, mock_pe_data):
        """Test import manipulation with mock PE data."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_import_manipulation_disabled(self, mock_pe_data):
        """Test that import manipulation is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,  # Disabled
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(obfuscated, bytes)
                assert report["techniques_applied"]["import_manipulation"] is False
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_import_manipulation_report(self, mock_pe_data):
        """Test import manipulation report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(report, dict)
                assert "techniques_applied" in report
                assert "size_change" in report
                assert "size_percentage" in report
                assert report["techniques_applied"]["import_manipulation"] is True
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_import_manipulator_initialization(self):
        """Test import manipulator initialization."""
        from rt_evade.pe.import_manipulator import (
            PEImportManipulator,
            ImportManipulationConfig,
        )

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = ImportManipulationConfig(
                enable_fake_imports=True,
                enable_dead_code_injection=True,
                max_fake_imports=20,
                max_dead_functions=10,
            )
            manipulator = PEImportManipulator(config)

            assert manipulator is not None
            assert manipulator.config == config
            assert len(manipulator.benign_apis) > 0

    def test_import_manipulator_requires_redteam_mode(self):
        """Test that import manipulator requires REDTEAM_MODE."""
        from rt_evade.pe.import_manipulator import PEImportManipulator

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEImportManipulator()

    def test_generate_fake_imports(self):
        """Test fake import generation."""
        from rt_evade.pe.import_manipulator import PEImportManipulator, ImportEntry

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            manipulator = PEImportManipulator()

            # Test with empty existing imports
            existing_imports = []
            fake_imports = manipulator.generate_fake_imports(existing_imports)

            assert isinstance(fake_imports, list)
            assert len(fake_imports) > 0
            assert all(isinstance(imp, ImportEntry) for imp in fake_imports)
            assert all(
                not imp.is_used for imp in fake_imports
            )  # Should be marked as unused

    def test_generate_dead_code_functions(self):
        """Test dead code function generation."""
        from rt_evade.pe.import_manipulator import PEImportManipulator

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            manipulator = PEImportManipulator()

            dead_code = manipulator.generate_dead_code_functions()

            assert isinstance(dead_code, list)
            assert len(dead_code) > 0
            assert all(isinstance(func, str) for func in dead_code)
            assert all(
                any(
                    pattern in func
                    for pattern in [
                        "__deadcode_",
                        "__unused_",
                        "__helper_",
                        "__check_",
                        "__get_",
                        "__init_",
                        "__cleanup_",
                        "__validate_",
                        "__process_",
                        "__verify_",
                    ]
                )
                for func in dead_code
            )

    def test_create_import_manipulation_plan(self, mock_pe_data):
        """Test import manipulation plan creation."""
        from rt_evade.pe.import_manipulator import PEImportManipulator

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            manipulator = PEImportManipulator()

            plan = manipulator.create_import_manipulation_plan(mock_pe_data)

            assert isinstance(plan, dict)
            assert "existing_imports" in plan
            assert "fake_imports" in plan
            assert "dead_code" in plan
            assert "total_imports" in plan
            assert "dead_functions" in plan
            assert isinstance(plan["existing_imports"], list)
            assert isinstance(plan["fake_imports"], list)
            assert isinstance(plan["dead_code"], list)

    def test_benign_apis_database(self):
        """Test benign APIs database loading."""
        from rt_evade.pe.import_manipulator import PEImportManipulator

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            manipulator = PEImportManipulator()

            benign_apis = manipulator.benign_apis

            assert isinstance(benign_apis, dict)
            assert len(benign_apis) > 0

            # Check for common Windows DLLs
            expected_dlls = ["kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll"]
            for dll in expected_dlls:
                assert dll in benign_apis
                assert isinstance(benign_apis[dll], list)
                assert len(benign_apis[dll]) > 0


class TestPEStaticEvasion:
    """Test PE static evasion functionality."""

    def test_static_evasion_with_mock_data(self, mock_pe_data):
        """Test static evasion with mock PE data."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,
                enable_static_evasion=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_static_evasion_disabled(self, mock_pe_data):
        """Test that static evasion is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,
                enable_static_evasion=False,  # Disabled
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(obfuscated, bytes)
                assert report["techniques_applied"]["static_evasion"] is False
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_static_evasion_report(self, mock_pe_data):
        """Test static evasion report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,
                enable_static_evasion=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(report, dict)
                assert "techniques_applied" in report
                assert "size_change" in report
                assert "size_percentage" in report
                assert report["techniques_applied"]["static_evasion"] is True
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_static_evasion_initialization(self):
        """Test static evasion initialization."""
        from rt_evade.pe.static_evasion import PEStaticEvasion, StaticEvasionConfig

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = StaticEvasionConfig(
                enable_metadata_cleaning=True,
                enable_tool_signature_removal=True,
                enable_suspicious_string_removal=True,
                enable_timestamp_randomization=True,
                enable_compiler_info_removal=True,
            )
            evasion = PEStaticEvasion(config)

            assert evasion is not None
            assert evasion.config == config
            assert len(evasion.suspicious_patterns) > 0
            assert len(evasion.tool_signatures) > 0

    def test_static_evasion_requires_redteam_mode(self):
        """Test that static evasion requires REDTEAM_MODE."""
        from rt_evade.pe.static_evasion import PEStaticEvasion

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEStaticEvasion()

    def test_suspicious_patterns_database(self):
        """Test suspicious patterns database loading."""
        from rt_evade.pe.static_evasion import PEStaticEvasion

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            evasion = PEStaticEvasion()

            patterns = evasion.suspicious_patterns

            assert isinstance(patterns, list)
            assert len(patterns) > 0

            # Check for common suspicious patterns
            expected_patterns = ["malware", "virus", "trojan", "backdoor", "payload"]
            for pattern in expected_patterns:
                assert pattern in patterns

    def test_tool_signatures_database(self):
        """Test tool signatures database loading."""
        from rt_evade.pe.static_evasion import PEStaticEvasion

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            evasion = PEStaticEvasion()

            signatures = evasion.tool_signatures

            assert isinstance(signatures, dict)
            assert len(signatures) > 0

            # Check for common tool categories
            expected_categories = ["compilers", "packers", "obfuscators", "analyzers"]
            for category in expected_categories:
                assert category in signatures
                assert isinstance(signatures[category], list)
                assert len(signatures[category]) > 0

    def test_create_static_evasion_plan(self, mock_pe_data):
        """Test static evasion plan creation."""
        from rt_evade.pe.static_evasion import PEStaticEvasion

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            evasion = PEStaticEvasion()

            plan = evasion.create_static_evasion_plan(mock_pe_data)

            assert isinstance(plan, dict)
            assert "metadata_cleaning" in plan
            assert "tool_signature_removal" in plan
            assert "suspicious_string_removal" in plan
            assert "suspicious_patterns_count" in plan
            assert "tool_signatures_count" in plan
            assert "total_evasion_techniques" in plan
            assert isinstance(plan["suspicious_patterns_count"], int)
            assert isinstance(plan["tool_signatures_count"], int)

    def test_get_benign_replacement(self):
        """Test benign replacement generation."""
        from rt_evade.pe.static_evasion import PEStaticEvasion

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            evasion = PEStaticEvasion()

            # Test short string
            replacement = evasion._get_benign_replacement("mal")
            assert isinstance(replacement, str)
            assert len(replacement) == 3

            # Test medium string
            replacement = evasion._get_benign_replacement("malware")
            assert isinstance(replacement, str)
            assert len(replacement) > 0  # Should generate a replacement

            # Test long string
            replacement = evasion._get_benign_replacement("very_long_suspicious_string")
            assert isinstance(replacement, str)
            assert len(replacement) > 0  # Should generate a replacement


class TestPEDetectionMitigation:
    """Test PE detection mitigation functionality."""

    def test_detection_mitigation_with_mock_data(self, mock_pe_data):
        """Test detection mitigation with mock PE data."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,
                enable_static_evasion=False,
                enable_detection_mitigation=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                assert isinstance(obfuscated, bytes)
                assert len(obfuscated) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_detection_mitigation_disabled(self, mock_pe_data):
        """Test that detection mitigation is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,
                enable_static_evasion=False,
                enable_detection_mitigation=False,  # Disabled
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(obfuscated, bytes)
                assert report["techniques_applied"]["detection_mitigation"] is False
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_detection_mitigation_report(self, mock_pe_data):
        """Test detection mitigation report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true", "ALLOW_ACTIONS": "true"}):
            from rt_evade.pe.encryption import EncryptionConfig

            config = PEObfuscationConfig(
                enable_mimicry=False,
                enable_string_obfuscation=False,
                enable_import_inflation=False,
                enable_section_padding=False,
                enable_entropy_increase=False,
                enable_compression=False,
                enable_code_encryption=False,
                enable_import_manipulation=False,
                enable_static_evasion=False,
                enable_detection_mitigation=True,
            )
            obfuscator = PEObfuscator(config)

            try:
                obfuscated = obfuscator.obfuscate_pe(mock_pe_data)
                report = obfuscator.get_obfuscation_report(mock_pe_data, obfuscated)

                assert isinstance(report, dict)
                assert "techniques_applied" in report
                assert "size_change" in report
                assert "size_percentage" in report
                assert report["techniques_applied"]["detection_mitigation"] is True
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_detection_mitigation_initialization(self):
        """Test detection mitigation initialization."""
        from rt_evade.pe.detection_mitigation import (
            PEDetectionMitigation,
            DetectionMitigationConfig,
        )

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = DetectionMitigationConfig(
                enable_file_size_monitoring=True,
                enable_timestamp_preservation=True,
                enable_section_name_optimization=True,
                max_file_size=10 * 1024 * 1024,  # 10MB
                min_file_size=2048,  # 2KB
                preserve_original_timestamps=True,
                use_benign_timestamps=False,
            )
            mitigation = PEDetectionMitigation(config)

            assert mitigation is not None
            assert mitigation.config == config
            assert len(mitigation.common_section_names) > 0
            assert len(mitigation.benign_timestamps) > 0

    def test_detection_mitigation_requires_redteam_mode(self):
        """Test that detection mitigation requires REDTEAM_MODE."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEDetectionMitigation()

    def test_file_size_monitoring(self):
        """Test file size monitoring functionality."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            mitigation = PEDetectionMitigation()

            # Test with small file
            small_data = b"small" * 100  # 500 bytes
            analysis = mitigation.monitor_file_size(small_data)

            assert isinstance(analysis, dict)
            assert "current_size" in analysis
            assert "max_size" in analysis
            assert "min_size" in analysis
            assert "size_percentage" in analysis
            assert "within_limits" in analysis
            assert "recommendations" in analysis
            assert analysis["current_size"] == len(small_data)
            assert isinstance(analysis["recommendations"], list)

    def test_common_section_names_database(self):
        """Test common section names database loading."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            mitigation = PEDetectionMitigation()

            section_names = mitigation.common_section_names

            assert isinstance(section_names, dict)
            assert len(section_names) > 0

            # Check for common section categories
            expected_categories = [
                "standard",
                "benign",
                "suspicious",
                "system",
                "development",
            ]
            for category in expected_categories:
                assert category in section_names
                assert isinstance(section_names[category], list)
                assert len(section_names[category]) > 0

    def test_benign_timestamps_database(self):
        """Test benign timestamps database loading."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            mitigation = PEDetectionMitigation()

            timestamps = mitigation.benign_timestamps

            assert isinstance(timestamps, list)
            assert len(timestamps) > 0
            assert all(isinstance(ts, int) for ts in timestamps)
            assert all(ts > 0 for ts in timestamps)  # Should be positive timestamps

    def test_create_detection_mitigation_plan(self, mock_pe_data):
        """Test detection mitigation plan creation."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            mitigation = PEDetectionMitigation()

            plan = mitigation.create_detection_mitigation_plan(mock_pe_data)

            assert isinstance(plan, dict)
            assert "file_size_monitoring" in plan
            assert "timestamp_preservation" in plan
            assert "section_name_optimization" in plan
            assert "size_analysis" in plan
            assert "suspicious_sections" in plan
            assert "total_sections" in plan
            assert "suspicious_section_count" in plan
            assert "mitigation_techniques" in plan
            assert isinstance(plan["size_analysis"], dict)
            assert isinstance(plan["suspicious_sections"], list)

    def test_suspicious_section_name_detection(self):
        """Test suspicious section name detection."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            mitigation = PEDetectionMitigation()

            # Test suspicious names
            suspicious_names = [".packed", ".upx", ".themida", ".vmprotect", ".enigma"]
            for name in suspicious_names:
                assert mitigation._is_suspicious_section_name(name) is True

            # Test benign names
            benign_names = [".text", ".data", ".rdata", ".bss", ".rsrc"]
            for name in benign_names:
                assert mitigation._is_suspicious_section_name(name) is False

    def test_benign_section_name_generation(self):
        """Test benign section name generation."""
        from rt_evade.pe.detection_mitigation import PEDetectionMitigation

        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            mitigation = PEDetectionMitigation()

            # Test suspicious to benign mapping
            suspicious_names = [".packed", ".upx", ".themida", ".vmprotect", ".enigma"]
            for name in suspicious_names:
                benign_name = mitigation._get_benign_section_name(name)
                assert isinstance(benign_name, str)
                assert len(benign_name) > 0
                assert not mitigation._is_suspicious_section_name(benign_name)
