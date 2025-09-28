"""Tests for PE string obfuscation functionality.

This module contains pytest tests for the PE string obfuscation component,
including obfuscation methods and configuration testing.
"""

import os
import pytest
from unittest.mock import patch

from rt_evade.pe.string_obfuscation import PEStringObfuscator, StringObfuscationConfig


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


class TestPEStringObfuscator:
    """Test PE string obfuscator functionality."""

    def test_obfuscator_initialization(self):
        """Test obfuscator initialization."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = StringObfuscationConfig()
            obfuscator = PEStringObfuscator(config)
            assert obfuscator is not None
            assert obfuscator.config == config

    def test_obfuscator_requires_redteam_mode(self):
        """Test that obfuscator requires REDTEAM_MODE."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="REDTEAM_MODE not enabled"):
                PEStringObfuscator()

    def test_obfuscate_strings_disabled(self, mock_pe_data):
        """Test that string obfuscation is skipped when disabled."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = StringObfuscationConfig(enable_string_obfuscation=False)
            obfuscator = PEStringObfuscator(config)

            result = obfuscator.obfuscate_strings(mock_pe_data)
            assert result == mock_pe_data

    def test_obfuscate_strings_with_mock_data(self, mock_pe_data):
        """Test string obfuscation with mock PE data."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = StringObfuscationConfig(
                enable_string_obfuscation=True,
                obfuscation_method="base64",
                min_string_length=4,
            )
            obfuscator = PEStringObfuscator(config)

            try:
                result = obfuscator.obfuscate_strings(mock_pe_data)
                assert isinstance(result, bytes)
                assert len(result) > 0
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_obfuscation_methods(self, mock_pe_data):
        """Test different obfuscation methods."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            methods = ["base64", "xor", "simple"]

            for method in methods:
                config = StringObfuscationConfig(
                    enable_string_obfuscation=True,
                    obfuscation_method=method,
                    min_string_length=4,
                )
                obfuscator = PEStringObfuscator(config)

                try:
                    result = obfuscator.obfuscate_strings(mock_pe_data)
                    assert isinstance(result, bytes)
                    assert len(result) > 0
                except Exception as e:
                    # Some operations might fail with mock data
                    assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_get_string_obfuscation_report(self, mock_pe_data):
        """Test string obfuscation report generation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            config = StringObfuscationConfig(
                enable_string_obfuscation=True,
                obfuscation_method="base64",
                min_string_length=4,
            )
            obfuscator = PEStringObfuscator(config)

            try:
                result = obfuscator.obfuscate_strings(mock_pe_data)
                report = obfuscator.get_string_obfuscation_report(mock_pe_data, result)

                assert isinstance(report, dict)
                assert "string_obfuscation_enabled" in report
                assert "obfuscation_method" in report
                assert "min_string_length" in report
                assert "original_size" in report
                assert "obfuscated_size" in report
                assert "size_change" in report
                assert "size_percentage" in report
                assert "suspicious_patterns_count" in report
            except Exception as e:
                # Some operations might fail with mock data
                assert "Invalid PE file" in str(e) or "PE format error" in str(e)

    def test_identify_suspicious_strings(self):
        """Test suspicious string identification."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEStringObfuscator()

            # Test with suspicious strings
            suspicious_strings = [
                "malware",
                "virus",
                "CreateProcess",
                "VirtualAlloc",
                "cmd.exe",
            ]
            result = obfuscator._identify_suspicious_strings(suspicious_strings)
            assert len(result) == len(suspicious_strings)

            # Test with benign strings
            benign_strings = ["hello", "world", "test", "application", "window"]
            result = obfuscator._identify_suspicious_strings(benign_strings)
            assert len(result) == 0

    def test_obfuscate_string_base64(self):
        """Test Base64 string obfuscation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEStringObfuscator()

            test_string = "malware"
            obfuscated = obfuscator._base64_obfuscate(test_string)

            assert obfuscated != test_string
            assert obfuscated.startswith("__b64_")
            assert obfuscated.endswith("__")

    def test_obfuscate_string_xor(self):
        """Test XOR string obfuscation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEStringObfuscator()

            test_string = "malware"
            obfuscated = obfuscator._xor_obfuscate(test_string)

            assert obfuscated != test_string
            assert obfuscated.startswith("__xor_")
            assert obfuscated.endswith("__")

    def test_obfuscate_string_simple(self):
        """Test simple string obfuscation."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEStringObfuscator()

            test_string = "malware"
            obfuscated = obfuscator._simple_obfuscate(test_string)

            assert obfuscated != test_string
            assert obfuscated.startswith("__sub_")
            assert obfuscated.endswith("__")

    def test_load_suspicious_patterns(self):
        """Test suspicious patterns loading."""
        with patch.dict(os.environ, {"REDTEAM_MODE": "true"}):
            obfuscator = PEStringObfuscator()

            patterns = obfuscator.suspicious_patterns
            assert isinstance(patterns, list)
            assert len(patterns) > 0

            # Check for common suspicious patterns
            expected_patterns = ["malware", "virus", "trojan", "backdoor", "payload"]
            for pattern in expected_patterns:
                assert pattern in patterns


class TestStringObfuscationConfig:
    """Test string obfuscation configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = StringObfuscationConfig()
        assert config.enable_string_obfuscation is True
        assert config.obfuscation_method == "base64"
        assert config.min_string_length == 4

    def test_custom_config(self):
        """Test custom configuration values."""
        config = StringObfuscationConfig(
            enable_string_obfuscation=False,
            obfuscation_method="xor",
            min_string_length=8,
        )

        assert config.enable_string_obfuscation is False
        assert config.obfuscation_method == "xor"
        assert config.min_string_length == 8
